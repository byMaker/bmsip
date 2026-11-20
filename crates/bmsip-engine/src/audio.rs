//! MODULE_CONTRACT: Hardware-agnostic 20 ms PCM audio bridge (`AudioPort`) and built-in Null/WAV/Queue adapters.
//! INVARIANTS: `#![forbid(unsafe_code)]`; no OS audio driver dependencies; fixed 160-sample (20 ms @ 8 kHz) mono frames.
//! RFC_REFS: RFC 3551 (20 ms G.711 packetization).

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use bmsip_media::WavPcm16;
pub use bmsip_media::{PCM_FRAME_SAMPLES_48KHZ_20MS, PCM_FRAME_SAMPLES_8KHZ_20MS};

/// Host-supplied audio I/O bridge consumed every 20 ms by [`crate::SipEngine`].
pub trait AudioPort: Send {
    /// Nominal mono PCM sample rate (`8000` or `48000` Hz) of frames exchanged with this port.
    fn sample_rate_hz(&self) -> u32 {
        8_000
    }

    /// Captures one 20 ms mono PCM frame (160 samples @ 8 kHz) for outbound RTP encoding.
    fn capture_20ms(&mut self) -> [i16; PCM_FRAME_SAMPLES_8KHZ_20MS];

    /// Captures one 20 ms mono PCM frame sized for [`Self::sample_rate_hz`] (`160` or `960` samples).
    fn capture_frame_20ms(&mut self) -> Vec<i16> {
        self.capture_20ms().to_vec()
    }

    /// Plays out one 20 ms decoded mono PCM frame from the jitter buffer.
    fn playout_20ms(&mut self, samples: &[i16]);
}

/// Silent audio port useful for signalling-only endpoints and unit tests.
#[derive(Debug, Default)]
pub struct NullAudioPort {
    pub playout_frames: u64,
}

impl AudioPort for NullAudioPort {
    fn capture_20ms(&mut self) -> [i16; PCM_FRAME_SAMPLES_8KHZ_20MS] {
        [0; PCM_FRAME_SAMPLES_8KHZ_20MS]
    }

    fn playout_20ms(&mut self, _samples: &[i16]) {
        self.playout_frames = self.playout_frames.saturating_add(1);
    }
}

/// Thread-safe handle to inspect audio captured by [`WavAudioPort`].
#[derive(Debug, Clone)]
pub struct WavAudioHandle {
    recorded: Arc<Mutex<Vec<i16>>>,
    sample_rate: u32,
}

impl WavAudioHandle {
    /// Returns all received playout samples as a [`WavPcm16`] clip.
    pub fn recorded_wav(&self) -> WavPcm16 {
        let guard = self.recorded.lock().unwrap_or_else(|e| e.into_inner());
        WavPcm16::new(self.sample_rate, guard.clone())
    }
}

/// Audio port streaming TX frames from a [`WavPcm16`] clip (looping or silence-padded) and recording RX frames.
#[derive(Debug)]
pub struct WavAudioPort {
    tx_samples: Vec<i16>,
    tx_cursor: usize,
    loop_tx: bool,
    sample_rate: u32,
    recorded: Arc<Mutex<Vec<i16>>>,
}

impl WavAudioPort {
    /// Creates a [`WavAudioPort`] and returns both the port and an inspection [`WavAudioHandle`].
    pub fn new(tx_clip: WavPcm16, loop_tx: bool) -> (Self, WavAudioHandle) {
        let rate = if tx_clip.sample_rate == 48_000 {
            48_000
        } else {
            8_000
        };
        let recorded = Arc::new(Mutex::new(Vec::new()));
        let handle = WavAudioHandle {
            recorded: Arc::clone(&recorded),
            sample_rate: rate,
        };
        let port = Self {
            tx_samples: tx_clip.samples,
            tx_cursor: 0,
            loop_tx,
            sample_rate: rate,
            recorded,
        };
        (port, handle)
    }

    fn next_frame(&mut self, len: usize) -> Vec<i16> {
        let mut frame = vec![0i16; len];
        if self.tx_samples.is_empty() {
            return frame;
        }
        for dst in &mut frame {
            if self.tx_cursor >= self.tx_samples.len() {
                if self.loop_tx {
                    self.tx_cursor = 0;
                } else {
                    break;
                }
            }
            *dst = self.tx_samples[self.tx_cursor];
            self.tx_cursor += 1;
        }
        frame
    }
}

impl AudioPort for WavAudioPort {
    fn sample_rate_hz(&self) -> u32 {
        self.sample_rate
    }

    fn capture_20ms(&mut self) -> [i16; PCM_FRAME_SAMPLES_8KHZ_20MS] {
        let vec = self.next_frame(PCM_FRAME_SAMPLES_8KHZ_20MS);
        let mut frame = [0i16; PCM_FRAME_SAMPLES_8KHZ_20MS];
        frame.copy_from_slice(&vec);
        frame
    }

    fn capture_frame_20ms(&mut self) -> Vec<i16> {
        let len = if self.sample_rate == 48_000 {
            PCM_FRAME_SAMPLES_48KHZ_20MS
        } else {
            PCM_FRAME_SAMPLES_8KHZ_20MS
        };
        self.next_frame(len)
    }

    fn playout_20ms(&mut self, samples: &[i16]) {
        if let Ok(mut guard) = self.recorded.lock() {
            guard.extend_from_slice(samples);
        }
    }
}

/// Non-blocking PCM frame handle for mobile (`CallKit`/`Oboe`) and FFI host integration.
#[derive(Debug, Clone)]
pub struct PcmAudioHandle {
    tx_queue: Arc<Mutex<VecDeque<[i16; PCM_FRAME_SAMPLES_8KHZ_20MS]>>>,
    rx_queue: Arc<Mutex<VecDeque<Vec<i16>>>>,
    max_queued_frames: usize,
}

impl PcmAudioHandle {
    /// Enqueues a 20 ms microphone frame from the host OS audio callback.
    pub fn push_captured_frame(&self, frame: [i16; PCM_FRAME_SAMPLES_8KHZ_20MS]) {
        if let Ok(mut guard) = self.tx_queue.lock() {
            if guard.len() >= self.max_queued_frames {
                guard.pop_front();
            }
            guard.push_back(frame);
        }
    }

    /// Pops the next decoded 20 ms speaker frame for the host OS audio callback.
    pub fn pop_playout_frame(&self) -> Option<Vec<i16>> {
        self.rx_queue
            .lock()
            .ok()
            .and_then(|mut guard| guard.pop_front())
    }
}

/// Queue-backed [`AudioPort`] bridging [`crate::SipEngine`] with external platform audio callbacks.
#[derive(Debug)]
pub struct PcmQueueAudioPort {
    tx_queue: Arc<Mutex<VecDeque<[i16; PCM_FRAME_SAMPLES_8KHZ_20MS]>>>,
    rx_queue: Arc<Mutex<VecDeque<Vec<i16>>>>,
    max_queued_frames: usize,
}

impl PcmQueueAudioPort {
    /// Creates a bounded [`PcmQueueAudioPort`] and its host-facing [`PcmAudioHandle`].
    pub fn new(max_queued_frames: usize) -> (Self, PcmAudioHandle) {
        let cap = max_queued_frames.max(4);
        let tx_queue = Arc::new(Mutex::new(VecDeque::new()));
        let rx_queue = Arc::new(Mutex::new(VecDeque::new()));
        let handle = PcmAudioHandle {
            tx_queue: Arc::clone(&tx_queue),
            rx_queue: Arc::clone(&rx_queue),
            max_queued_frames: cap,
        };
        let port = Self {
            tx_queue,
            rx_queue,
            max_queued_frames: cap,
        };
        (port, handle)
    }
}

impl AudioPort for PcmQueueAudioPort {
    fn capture_20ms(&mut self) -> [i16; PCM_FRAME_SAMPLES_8KHZ_20MS] {
        self.tx_queue
            .lock()
            .ok()
            .and_then(|mut guard| guard.pop_front())
            .unwrap_or([0; PCM_FRAME_SAMPLES_8KHZ_20MS])
    }

    fn playout_20ms(&mut self, samples: &[i16]) {
        if let Ok(mut guard) = self.rx_queue.lock() {
            if guard.len() >= self.max_queued_frames {
                guard.pop_front();
            }
            guard.push_back(samples.to_vec());
        }
    }
}
