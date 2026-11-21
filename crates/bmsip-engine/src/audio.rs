//! MODULE_CONTRACT: Hardware-agnostic 20 ms PCM audio bridge (`AudioPort`) and built-in Null/WAV/Queue adapters.
//! INVARIANTS: `#![forbid(unsafe_code)]`; no OS audio driver dependencies; fixed 160-sample (20 ms @ 8 kHz) mono frames.
//! RFC_REFS: RFC 3551 (20 ms G.711 packetization).

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use bmsip_media::{resample_pcm_20ms, WavPcm16};
pub use bmsip_media::{
    PCM_FRAME_SAMPLES_16KHZ_20MS, PCM_FRAME_SAMPLES_48KHZ_20MS, PCM_FRAME_SAMPLES_8KHZ_20MS,
};

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

/// Audio port streaming TX frames from a [`WavPcm16`] clip (looping or silence-padded) and optionally recording RX frames.
#[derive(Debug)]
pub struct WavAudioPort {
    tx_samples: Vec<i16>,
    tx_cursor: usize,
    loop_tx: bool,
    sample_rate: u32,
    record_rx: bool,
    max_recorded_samples: Option<usize>,
    recorded: Arc<Mutex<Vec<i16>>>,
}

impl WavAudioPort {
    /// Creates a [`WavAudioPort`] with RX recording enabled and returns both the port and an inspection [`WavAudioHandle`].
    pub fn new(tx_clip: WavPcm16, loop_tx: bool) -> (Self, WavAudioHandle) {
        Self::new_with_recording(tx_clip, loop_tx, true)
    }

    /// Creates a [`WavAudioPort`] with explicit control over whether received RX frames are buffered in memory.
    pub fn new_with_recording(
        tx_clip: WavPcm16,
        loop_tx: bool,
        record_rx: bool,
    ) -> (Self, WavAudioHandle) {
        let rate = match tx_clip.sample_rate {
            48_000 => 48_000,
            16_000 => 16_000,
            _ => 8_000,
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
            record_rx,
            max_recorded_samples: None,
            recorded,
        };
        (port, handle)
    }

    /// Caps the maximum number of RX PCM samples retained in memory (`None` = unbounded while `record_rx` is true).
    pub fn with_max_recorded_samples(mut self, max_samples: Option<usize>) -> Self {
        self.max_recorded_samples = max_samples;
        self
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
        let len = match self.sample_rate {
            48_000 => PCM_FRAME_SAMPLES_48KHZ_20MS,
            16_000 => PCM_FRAME_SAMPLES_16KHZ_20MS,
            _ => PCM_FRAME_SAMPLES_8KHZ_20MS,
        };
        self.next_frame(len)
    }

    fn playout_20ms(&mut self, samples: &[i16]) {
        if !self.record_rx {
            return;
        }
        if let Ok(mut guard) = self.recorded.lock() {
            if let Some(cap) = self.max_recorded_samples {
                let remaining = cap.saturating_sub(guard.len());
                if remaining > 0 {
                    let take = remaining.min(samples.len());
                    guard.extend_from_slice(&samples[..take]);
                }
            } else {
                guard.extend_from_slice(samples);
            }
        }
    }
}

fn normalize_audio_sample_rate(sample_rate_hz: u32) -> (u32, usize) {
    match sample_rate_hz {
        48_000 => (48_000, PCM_FRAME_SAMPLES_48KHZ_20MS),
        16_000 => (16_000, PCM_FRAME_SAMPLES_16KHZ_20MS),
        _ => (8_000, PCM_FRAME_SAMPLES_8KHZ_20MS),
    }
}

/// Non-blocking PCM frame handle for mobile (`CallKit`/`Oboe`) and FFI host integration.
#[derive(Debug, Clone)]
pub struct PcmAudioHandle {
    tx_queue: Arc<Mutex<VecDeque<Vec<i16>>>>,
    rx_queue: Arc<Mutex<VecDeque<Vec<i16>>>>,
    max_queued_frames: usize,
    sample_rate_hz: u32,
    frame_samples: usize,
}

impl PcmAudioHandle {
    /// Returns the configured mono PCM sample rate (`8000`, `16000`, or `48000` Hz).
    pub fn sample_rate_hz(&self) -> u32 {
        self.sample_rate_hz
    }

    /// Returns the expected number of samples per 20 ms frame (`160`, `320`, or `960`).
    pub fn frame_samples(&self) -> usize {
        self.frame_samples
    }

    /// Enqueues an 8 kHz (160-sample) 20 ms microphone frame, resampling automatically if the port runs at 16/48 kHz.
    pub fn push_captured_frame(&self, frame: [i16; PCM_FRAME_SAMPLES_8KHZ_20MS]) {
        let samples = if self.frame_samples == PCM_FRAME_SAMPLES_8KHZ_20MS {
            frame.to_vec()
        } else {
            resample_pcm_20ms(&frame, self.frame_samples)
                .unwrap_or_else(|_| vec![0; self.frame_samples])
        };
        let _ = self.push_captured_samples(samples);
    }

    /// Enqueues a 20 ms microphone frame matching [`Self::frame_samples`].
    ///
    /// Returns `Err(expected_len)` if `samples.len()` does not match `frame_samples()`.
    pub fn push_captured_samples(&self, samples: Vec<i16>) -> Result<(), usize> {
        if samples.len() != self.frame_samples {
            return Err(self.frame_samples);
        }
        if let Ok(mut guard) = self.tx_queue.lock() {
            if guard.len() >= self.max_queued_frames {
                guard.pop_front();
            }
            guard.push_back(samples);
        }
        Ok(())
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
    tx_queue: Arc<Mutex<VecDeque<Vec<i16>>>>,
    rx_queue: Arc<Mutex<VecDeque<Vec<i16>>>>,
    max_queued_frames: usize,
    sample_rate_hz: u32,
    frame_samples: usize,
}

impl PcmQueueAudioPort {
    /// Creates a bounded 8 kHz [`PcmQueueAudioPort`] and its host-facing [`PcmAudioHandle`].
    pub fn new(max_queued_frames: usize) -> (Self, PcmAudioHandle) {
        Self::new_with_sample_rate(8_000, max_queued_frames)
    }

    /// Creates a bounded [`PcmQueueAudioPort`] at `8000`, `16000`, or `48000` Hz for narrowband or HD Voice.
    pub fn new_with_sample_rate(
        sample_rate_hz: u32,
        max_queued_frames: usize,
    ) -> (Self, PcmAudioHandle) {
        let cap = max_queued_frames.max(4);
        let (rate, frame_samples) = normalize_audio_sample_rate(sample_rate_hz);
        let tx_queue = Arc::new(Mutex::new(VecDeque::new()));
        let rx_queue = Arc::new(Mutex::new(VecDeque::new()));
        let handle = PcmAudioHandle {
            tx_queue: Arc::clone(&tx_queue),
            rx_queue: Arc::clone(&rx_queue),
            max_queued_frames: cap,
            sample_rate_hz: rate,
            frame_samples,
        };
        let port = Self {
            tx_queue,
            rx_queue,
            max_queued_frames: cap,
            sample_rate_hz: rate,
            frame_samples,
        };
        (port, handle)
    }
}

impl AudioPort for PcmQueueAudioPort {
    fn sample_rate_hz(&self) -> u32 {
        self.sample_rate_hz
    }

    fn capture_20ms(&mut self) -> [i16; PCM_FRAME_SAMPLES_8KHZ_20MS] {
        let frame = self.capture_frame_20ms();
        let mut out = [0i16; PCM_FRAME_SAMPLES_8KHZ_20MS];
        if frame.len() == PCM_FRAME_SAMPLES_8KHZ_20MS {
            out.copy_from_slice(&frame);
        } else if let Ok(down) = resample_pcm_20ms(&frame, PCM_FRAME_SAMPLES_8KHZ_20MS) {
            let n = down.len().min(PCM_FRAME_SAMPLES_8KHZ_20MS);
            out[..n].copy_from_slice(&down[..n]);
        }
        out
    }

    fn capture_frame_20ms(&mut self) -> Vec<i16> {
        self.tx_queue
            .lock()
            .ok()
            .and_then(|mut guard| guard.pop_front())
            .unwrap_or_else(|| vec![0; self.frame_samples])
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
