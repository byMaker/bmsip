//! MODULE_CONTRACT: Adaptive jitter buffer with 16-bit sequence wraparound reordering and decayed packet-loss concealment (PLC).
//! INVARIANTS: Reorders out-of-order frames, drops late/duplicate frames, adapts `target_depth_frames` within `[min_depth_frames, max_depth_frames]` based on jitter, and bounds buffered memory.
//! RFC_REFS: RFC 3550 Section 5.1 (16-bit sequence rollover), Section 6.4.1 (interarrival jitter).

use std::collections::BTreeMap;

/// Configuration for [`AdaptiveJitterBuffer`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JitterBufferConfig {
    pub min_depth_frames: usize,
    pub max_depth_frames: usize,
    pub initial_depth_frames: usize,
    pub frame_samples: usize,
}

impl Default for JitterBufferConfig {
    fn default() -> Self {
        Self {
            min_depth_frames: 2,
            max_depth_frames: 12,
            initial_depth_frames: 3,
            frame_samples: 160,
        }
    }
}

/// Output frame produced by [`AdaptiveJitterBuffer::pop`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlayoutFrame {
    /// Decoded in-order audio frame.
    Normal(Vec<i16>),
    /// Concealed frame synthesized for a missing packet (attenuated last good frame).
    Concealed(Vec<i16>),
    /// Silence emitted while priming buffer depth or after sustained stream pause.
    Buffering(Vec<i16>),
}

impl PlayoutFrame {
    /// Returns the underlying PCM samples slice.
    pub fn samples(&self) -> &[i16] {
        match self {
            Self::Normal(s) | Self::Concealed(s) | Self::Buffering(s) => s.as_slice(),
        }
    }
}

/// Reordering adaptive jitter buffer for 20 ms mono PCM frames.
#[derive(Debug, Clone)]
pub struct AdaptiveJitterBuffer {
    config: JitterBufferConfig,
    frames: BTreeMap<u32, Vec<i16>>,
    primed: bool,
    initialized: bool,
    highest_ext_seq: u32,
    next_playout_seq: u32,
    target_depth_frames: usize,
    last_good_frame: Vec<i16>,
    last_emitted_sample: i16,
    consecutive_concealed: usize,
    late_drops: u64,
    duplicate_drops: u64,
    concealed_frames: u64,
}

impl AdaptiveJitterBuffer {
    /// Creates an [`AdaptiveJitterBuffer`] from `config`.
    pub fn new(config: JitterBufferConfig) -> Self {
        let clamped_init = config
            .initial_depth_frames
            .clamp(config.min_depth_frames, config.max_depth_frames.max(1));
        Self {
            config,
            frames: BTreeMap::new(),
            primed: false,
            initialized: false,
            highest_ext_seq: 0,
            next_playout_seq: 0,
            target_depth_frames: clamped_init,
            last_good_frame: vec![0; config.frame_samples],
            last_emitted_sample: 0,
            consecutive_concealed: 0,
            late_drops: 0,
            duplicate_drops: 0,
            concealed_frames: 0,
        }
    }

    /// Inserts a decoded PCM frame and adapts target depth using `jitter_samples`.
    pub fn push(&mut self, seq: u16, pcm_frame: Vec<i16>, jitter_samples: u32) {
        self.update_target_depth(jitter_samples);

        if !self.initialized {
            self.initialized = true;
            // Anchor around 0x0001_0000 so slightly out-of-order negative offsets stay non-negative.
            let anchor = 0x0001_0000u32 + u32::from(seq);
            self.highest_ext_seq = anchor;
            self.next_playout_seq = anchor;
            self.frames.insert(anchor, pcm_frame);
            return;
        }

        let highest_low16 = (self.highest_ext_seq & 0xffff) as u16;
        let diff = seq.wrapping_sub(highest_low16) as i16;
        let ext_seq = if diff >= 0 {
            let candidate = self.highest_ext_seq + u32::from(diff as u16);
            self.highest_ext_seq = candidate;
            candidate
        } else {
            let back = (-i32::from(diff)) as u32;
            self.highest_ext_seq.saturating_sub(back)
        };

        if ext_seq < self.next_playout_seq {
            self.late_drops += 1;
            return;
        }
        if self.frames.contains_key(&ext_seq) {
            self.duplicate_drops += 1;
            return;
        }

        self.frames.insert(ext_seq, pcm_frame);

        let cap = self.config.max_depth_frames.saturating_mul(2).max(4);
        while self.frames.len() > cap {
            if let Some((&oldest_seq, _)) = self.frames.iter().next() {
                self.frames.remove(&oldest_seq);
                if oldest_seq >= self.next_playout_seq {
                    self.next_playout_seq = oldest_seq + 1;
                }
            } else {
                break;
            }
        }
    }

    /// Pops the next 20 ms playout frame, emitting concealed audio or buffering silence when needed.
    pub fn pop(&mut self) -> PlayoutFrame {
        if !self.initialized {
            self.last_emitted_sample = 0;
            return PlayoutFrame::Buffering(vec![0; self.config.frame_samples]);
        }

        if !self.primed {
            if self.frames.len() < self.target_depth_frames {
                self.last_emitted_sample = 0;
                return PlayoutFrame::Buffering(vec![0; self.config.frame_samples]);
            }
            self.primed = true;
        }

        if let Some(mut pcm) = self.frames.remove(&self.next_playout_seq) {
            self.next_playout_seq += 1;
            self.last_good_frame = pcm.clone();
            if self.consecutive_concealed > 0 && self.config.frame_samples >= 16 {
                let fade_len = (self.config.frame_samples / 8).min(32);
                crossfade_head(&mut pcm, self.last_emitted_sample, fade_len);
            }
            self.consecutive_concealed = 0;
            self.last_emitted_sample = *pcm.last().unwrap_or(&0);
            return PlayoutFrame::Normal(pcm);
        }

        if self.frames.is_empty() && self.consecutive_concealed >= 4 {
            self.primed = false;
            self.last_emitted_sample = 0;
            return PlayoutFrame::Buffering(vec![0; self.config.frame_samples]);
        }

        self.next_playout_seq += 1;
        self.consecutive_concealed += 1;
        self.concealed_frames += 1;

        for sample in &mut self.last_good_frame {
            *sample = ((*sample as i32 * 3) / 4) as i16;
        }
        let mut concealed = self.last_good_frame.clone();
        if self.config.frame_samples >= 16 {
            let fade_len = (self.config.frame_samples / 8).min(32);
            crossfade_head(&mut concealed, self.last_emitted_sample, fade_len);
        }
        self.last_emitted_sample = *concealed.last().unwrap_or(&0);
        PlayoutFrame::Concealed(concealed)
    }

    /// Returns the current adaptive target playout depth in frames.
    pub fn target_depth_frames(&self) -> usize {
        self.target_depth_frames
    }

    /// Returns counts of `(late_drops, duplicate_drops, concealed_frames)`.
    pub fn counters(&self) -> (u64, u64, u64) {
        (self.late_drops, self.duplicate_drops, self.concealed_frames)
    }

    fn update_target_depth(&mut self, jitter_samples: u32) {
        let frame_samples = self.config.frame_samples.max(1);
        let jitter_frames = (jitter_samples as usize).div_ceil(frame_samples);
        let desired = (jitter_frames + 1).clamp(
            self.config.min_depth_frames,
            self.config
                .max_depth_frames
                .max(self.config.min_depth_frames),
        );

        if desired > self.target_depth_frames {
            self.target_depth_frames = desired;
        } else if desired < self.target_depth_frames {
            self.target_depth_frames -= 1;
        }
    }
}

fn crossfade_head(samples: &mut [i16], prev_sample: i16, fade_len: usize) {
    let n = fade_len.min(samples.len());
    if n == 0 {
        return;
    }
    let denom = i32::from(n as i16);
    let prev = i32::from(prev_sample);
    for (idx, sample) in samples.iter_mut().take(n).enumerate() {
        let i = i32::from(idx as i16);
        let blended = (prev * (denom - i) + i32::from(*sample) * i) / denom;
        *sample = blended as i16;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reorders_out_of_order_and_conceals_missing_packet() {
        let cfg = JitterBufferConfig {
            min_depth_frames: 2,
            max_depth_frames: 8,
            initial_depth_frames: 2,
            frame_samples: 4,
        };
        let mut jb = AdaptiveJitterBuffer::new(cfg);

        // Push 1, 3, 4 (missing 2) and duplicate 3.
        jb.push(1, vec![100; 4], 0);
        jb.push(4, vec![400; 4], 0);
        jb.push(3, vec![300; 4], 0);
        jb.push(3, vec![300; 4], 0);

        assert_eq!(jb.pop(), PlayoutFrame::Normal(vec![100; 4]));
        assert_eq!(jb.pop(), PlayoutFrame::Concealed(vec![75; 4]));
        assert_eq!(jb.pop(), PlayoutFrame::Normal(vec![300; 4]));
        assert_eq!(jb.pop(), PlayoutFrame::Normal(vec![400; 4]));
        assert_eq!(jb.counters(), (0, 1, 1));
    }

    #[test]
    fn adapts_target_depth_when_jitter_rises() {
        let cfg = JitterBufferConfig::default();
        let mut jb = AdaptiveJitterBuffer::new(cfg);
        assert_eq!(jb.target_depth_frames(), 3);

        // 800 samples of jitter = 5 frames -> desired depth = 6
        jb.push(10, vec![0; 160], 800);
        assert_eq!(jb.target_depth_frames(), 6);

        // Drops gently by 1 when jitter returns to 0
        jb.push(11, vec![0; 160], 0);
        assert_eq!(jb.target_depth_frames(), 5);
    }

    #[test]
    fn handles_16bit_sequence_wraparound() {
        let cfg = JitterBufferConfig {
            min_depth_frames: 2,
            max_depth_frames: 8,
            initial_depth_frames: 2,
            frame_samples: 2,
        };
        let mut jb = AdaptiveJitterBuffer::new(cfg);

        jb.push(65534, vec![10; 2], 0);
        jb.push(0, vec![30; 2], 0);
        jb.push(65535, vec![20; 2], 0);

        assert_eq!(jb.pop(), PlayoutFrame::Normal(vec![10; 2]));
        assert_eq!(jb.pop(), PlayoutFrame::Normal(vec![20; 2]));
        assert_eq!(jb.pop(), PlayoutFrame::Normal(vec![30; 2]));
    }

    #[test]
    fn concealed_frame_crossfades_boundary_without_phase_click() {
        let cfg = JitterBufferConfig {
            min_depth_frames: 2,
            max_depth_frames: 8,
            initial_depth_frames: 2,
            frame_samples: 160,
        };
        let mut jb = AdaptiveJitterBuffer::new(cfg);

        // Ramp from +8000 down to -8000 so uncrossfaded wraparound would jump by ~14000.
        let ramp: Vec<i16> = (0..160).map(|i| 8000 - (i as i16 * 100)).collect();
        jb.push(1, ramp.clone(), 0);
        jb.push(3, ramp, 0);

        let f1 = jb.pop();
        let f2 = jb.pop();
        let f3 = jb.pop();
        assert!(matches!(f1, PlayoutFrame::Normal(_)));
        assert!(matches!(f2, PlayoutFrame::Concealed(_)));
        assert!(matches!(f3, PlayoutFrame::Normal(_)));

        let jump_into_plc = (i32::from(f2.samples()[0]) - i32::from(f1.samples()[159])).abs();
        let jump_out_of_plc = (i32::from(f3.samples()[0]) - i32::from(f2.samples()[159])).abs();
        assert!(
            jump_into_plc < 500,
            "expected smooth PLC entry jump < 500, got {jump_into_plc}"
        );
        assert!(
            jump_out_of_plc < 500,
            "expected smooth PLC recovery jump < 500, got {jump_out_of_plc}"
        );
    }
}
