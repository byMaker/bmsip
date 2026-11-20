//! MODULE_CONTRACT: Linux live microphone/speaker `AudioPort` adapter using PipeWire/PulseAudio (`pacat`) or ALSA (`arecord`/`aplay`).
//! INVARIANTS: `#![forbid(unsafe_code)]`; non-blocking 20 ms `AudioPort` queues so slow OS audio I/O never stalls `SipEngine`; terminates child processes cleanly on `Drop`.
//! RFC_REFS: RFC 3551 (20 ms 8 kHz mono PCM16).

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};

use bmsip_engine::bmsip_media::WavPcm16;
use bmsip_engine::{AudioPort, PCM_FRAME_SAMPLES_8KHZ_20MS};

const MAX_QUEUED_FRAMES: usize = 16;
const FRAME_BYTES: usize = PCM_FRAME_SAMPLES_8KHZ_20MS * 2;

/// Thread-safe handle for inspecting playout audio captured during live sessions.
#[derive(Debug, Clone)]
pub struct LiveAudioHandle {
    recorded: Arc<Mutex<Vec<i16>>>,
}

impl LiveAudioHandle {
    /// Returns all received RX playout samples as a [`WavPcm16`] clip.
    pub fn recorded_wav(&self) -> WavPcm16 {
        let guard = self.recorded.lock().unwrap_or_else(|e| e.into_inner());
        WavPcm16::new(8000, guard.clone())
    }
}

/// Live Linux [`AudioPort`] streaming 8 kHz mono 16-bit PCM via `pacat` (PipeWire/PulseAudio) or ALSA.
pub struct LiveLinuxAudioPort {
    stop: Arc<AtomicBool>,
    tx_queue: Arc<Mutex<VecDeque<[i16; PCM_FRAME_SAMPLES_8KHZ_20MS]>>>,
    rx_queue: Arc<(Mutex<VecDeque<[i16; PCM_FRAME_SAMPLES_8KHZ_20MS]>>, Condvar)>,
    recorded: Arc<Mutex<Vec<i16>>>,
    rec_child: Option<Child>,
    play_child: Option<Child>,
    rec_thread: Option<JoinHandle<()>>,
    play_thread: Option<JoinHandle<()>>,
}

impl LiveLinuxAudioPort {
    /// Spawns live Linux audio capture/playback subprocesses, falling back gracefully if audio hardware is unavailable.
    pub fn spawn() -> (Self, LiveAudioHandle) {
        let stop = Arc::new(AtomicBool::new(false));
        let tx_queue = Arc::new(Mutex::new(
            VecDeque::<[i16; PCM_FRAME_SAMPLES_8KHZ_20MS]>::new(),
        ));
        let rx_queue = Arc::new((
            Mutex::new(VecDeque::<[i16; PCM_FRAME_SAMPLES_8KHZ_20MS]>::new()),
            Condvar::new(),
        ));
        let recorded = Arc::new(Mutex::new(Vec::new()));
        let handle = LiveAudioHandle {
            recorded: Arc::clone(&recorded),
        };

        let mut rec_child = spawn_recorder();
        let rec_thread = rec_child.as_mut().and_then(|child| {
            let mut stdout = child.stdout.take()?;
            let stop_flag = Arc::clone(&stop);
            let q = Arc::clone(&tx_queue);
            thread::Builder::new()
                .name("bmsip-live-rec".to_string())
                .spawn(move || {
                    let mut buf = [0u8; FRAME_BYTES];
                    while !stop_flag.load(Ordering::Relaxed) {
                        if stdout.read_exact(&mut buf).is_err() {
                            break;
                        }
                        let mut frame = [0i16; PCM_FRAME_SAMPLES_8KHZ_20MS];
                        for (dst, pair) in frame.iter_mut().zip(buf.as_chunks::<2>().0) {
                            *dst = i16::from_le_bytes(*pair);
                        }
                        if let Ok(mut guard) = q.lock() {
                            if guard.len() >= MAX_QUEUED_FRAMES {
                                guard.pop_front();
                            }
                            guard.push_back(frame);
                        }
                    }
                })
                .ok()
        });

        let mut play_child = spawn_player();
        let play_thread = play_child.as_mut().and_then(|child| {
            let mut stdin = child.stdin.take()?;
            let stop_flag = Arc::clone(&stop);
            let q = Arc::clone(&rx_queue);
            thread::Builder::new()
                .name("bmsip-live-play".to_string())
                .spawn(move || {
                    let mut out_bytes = [0u8; FRAME_BYTES];
                    loop {
                        let next_frame = {
                            let Ok(guard) = q.0.lock() else {
                                break;
                            };
                            let Ok(mut guard) = q.1.wait_while(guard, |dq| {
                                dq.is_empty() && !stop_flag.load(Ordering::Relaxed)
                            }) else {
                                break;
                            };
                            if stop_flag.load(Ordering::Relaxed) && guard.is_empty() {
                                break;
                            }
                            guard.pop_front()
                        };
                        let Some(frame) = next_frame else {
                            if stop_flag.load(Ordering::Relaxed) {
                                break;
                            }
                            continue;
                        };
                        for (dst, &sample) in
                            out_bytes.as_chunks_mut::<2>().0.iter_mut().zip(&frame)
                        {
                            *dst = sample.to_le_bytes();
                        }
                        if stdin.write_all(&out_bytes).is_err() {
                            break;
                        }
                    }
                })
                .ok()
        });

        let port = Self {
            stop,
            tx_queue,
            rx_queue,
            recorded,
            rec_child,
            play_child,
            rec_thread,
            play_thread,
        };
        (port, handle)
    }
}

impl AudioPort for LiveLinuxAudioPort {
    fn capture_20ms(&mut self) -> [i16; PCM_FRAME_SAMPLES_8KHZ_20MS] {
        self.tx_queue
            .lock()
            .ok()
            .and_then(|mut guard| guard.pop_front())
            .unwrap_or([0; PCM_FRAME_SAMPLES_8KHZ_20MS])
    }

    fn playout_20ms(&mut self, samples: &[i16]) {
        if let Ok(mut rec) = self.recorded.lock() {
            rec.extend_from_slice(samples);
        }
        let mut frame = [0i16; PCM_FRAME_SAMPLES_8KHZ_20MS];
        let copy_len = samples.len().min(PCM_FRAME_SAMPLES_8KHZ_20MS);
        frame[..copy_len].copy_from_slice(&samples[..copy_len]);

        if let Ok(mut guard) = self.rx_queue.0.lock() {
            if guard.len() >= MAX_QUEUED_FRAMES {
                guard.pop_front();
            }
            guard.push_back(frame);
            self.rx_queue.1.notify_all();
        }
    }
}

impl Drop for LiveLinuxAudioPort {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.rx_queue.1.notify_all();

        if let Some(mut child) = self.rec_child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        if let Some(mut child) = self.play_child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        if let Some(h) = self.rec_thread.take() {
            let _ = h.join();
        }
        if let Some(h) = self.play_thread.take() {
            let _ = h.join();
        }
    }
}

fn spawn_recorder() -> Option<Child> {
    if let Ok(child) = Command::new("pacat")
        .args([
            "--record",
            "--raw",
            "--format=s16le",
            "--rate=8000",
            "--channels=1",
            "--latency-msec=20",
            "--client-name=bmsip-cli",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
        return Some(child);
    }

    Command::new("arecord")
        .args(["-q", "-t", "raw", "-f", "S16_LE", "-r", "8000", "-c", "1"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()
}

fn spawn_player() -> Option<Child> {
    if let Ok(child) = Command::new("pacat")
        .args([
            "--playback",
            "--raw",
            "--format=s16le",
            "--rate=8000",
            "--channels=1",
            "--latency-msec=20",
            "--client-name=bmsip-cli",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        return Some(child);
    }

    Command::new("aplay")
        .args(["-q", "-t", "raw", "-f", "S16_LE", "-r", "8000", "-c", "1"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok()
}
