//! MODULE_CONTRACT: Adaptive jitter buffer with 16-bit sequence wraparound reordering, automatic RTP packet-duration (`ptime`) framing to fixed 20 ms playout blocks, and decayed packet-loss concealment (PLC).
//! INVARIANTS: Reorders out-of-order packets in true RTP sequence space regardless of packet duration (`2.5`–`120` ms), assembles exact `frame_samples` playout frames, drops late/duplicate packets, adapts `target_depth_frames` within `[min_depth_frames, max_depth_frames]` based on jitter, and bounds buffered memory.
//! RFC_REFS: RFC 3550 Section 5.1 (16-bit sequence rollover), Section 6.4.1 (interarrival jitter).

use std::collections::{BTreeMap, BTreeSet, VecDeque};

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
    /// Comfort noise frame synthesized under RFC 3389 DTX/CN silence.
    ComfortNoise(Vec<i16>),
    /// Silence emitted while priming buffer depth or after sustained stream pause.
    Buffering(Vec<i16>),
}

impl PlayoutFrame {
    /// Returns the underlying PCM samples slice.
    pub fn samples(&self) -> &[i16] {
        match self {
            Self::Normal(s) | Self::Concealed(s) | Self::ComfortNoise(s) | Self::Buffering(s) => {
                s.as_slice()
            }
        }
    }
}

/// Hysteresis window (`250` clean 20 ms pops = `5.0 s`) before decaying an underrun-induced depth floor by 1 frame.
const UNDERRUN_FLOOR_DECAY_POPS: u32 = 250;
/// Low-jitter packet window (`50` packets = `1.0 s`) before shrinking `target_depth_frames` below `initial_depth_frames`.
const SUB_INITIAL_SHRINK_PACKETS: u32 = 50;

/// Reordering adaptive jitter buffer assembling arbitrary-duration RTP audio packets into 20 ms mono PCM frames.
#[derive(Debug, Clone)]
pub struct AdaptiveJitterBuffer {
    config: JitterBufferConfig,
    frames: BTreeMap<u32, Vec<i16>>,
    queued_frame_samples: usize,
    playout_fifo: VecDeque<i16>,
    nominal_pkt_samples: usize,
    skipped_seqs: BTreeSet<u32>,
    primed: bool,
    initialized: bool,
    recovering_from_underrun: bool,
    highest_ext_seq: u32,
    next_playout_seq: u32,
    target_depth_frames: usize,
    underrun_floor_frames: usize,
    underrun_free_pops: u32,
    low_jitter_packets: u32,
    excess_depth_ticks: u32,
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
        let frame_samples = config.frame_samples.max(1);
        let max_depth = config.max_depth_frames.max(config.min_depth_frames).max(1);
        let clamped_init = config
            .initial_depth_frames
            .clamp(config.min_depth_frames, max_depth);
        Self {
            config,
            frames: BTreeMap::new(),
            queued_frame_samples: 0,
            playout_fifo: VecDeque::with_capacity(frame_samples.saturating_mul(4)),
            nominal_pkt_samples: frame_samples,
            skipped_seqs: BTreeSet::new(),
            primed: false,
            initialized: false,
            recovering_from_underrun: false,
            highest_ext_seq: 0,
            next_playout_seq: 0,
            target_depth_frames: clamped_init,
            underrun_floor_frames: config.min_depth_frames,
            underrun_free_pops: 0,
            low_jitter_packets: 0,
            excess_depth_ticks: 0,
            last_good_frame: vec![0; frame_samples],
            last_emitted_sample: 0,
            consecutive_concealed: 0,
            late_drops: 0,
            duplicate_drops: 0,
            concealed_frames: 0,
        }
    }

    fn insert_frame(&mut self, ext_seq: u32, pcm_frame: Vec<i16>) {
        self.queued_frame_samples = self.queued_frame_samples.saturating_add(pcm_frame.len());
        if let Some(prev) = self.frames.insert(ext_seq, pcm_frame) {
            self.queued_frame_samples = self.queued_frame_samples.saturating_sub(prev.len());
        }
    }

    fn remove_frame(&mut self, ext_seq: u32) -> Option<Vec<i16>> {
        let removed = self.frames.remove(&ext_seq)?;
        self.queued_frame_samples = self.queued_frame_samples.saturating_sub(removed.len());
        Some(removed)
    }

    fn total_buffered_samples(&self) -> usize {
        self.playout_fifo
            .len()
            .saturating_add(self.queued_frame_samples)
    }

    fn update_last_good_tail(&mut self, samples: &[i16]) {
        let cap = self.last_good_frame.len();
        if cap == 0 || samples.is_empty() {
            return;
        }
        if samples.len() >= cap {
            self.last_good_frame
                .copy_from_slice(&samples[samples.len() - cap..]);
        } else {
            let k = samples.len();
            self.last_good_frame.copy_within(k..cap, 0);
            self.last_good_frame[cap - k..].copy_from_slice(samples);
        }
    }

    fn synthesize_missing_plc(&mut self, plc_len: usize, prev_sample: i16) -> Vec<i16> {
        let cap = self.last_good_frame.len().max(1);
        let len = plc_len.clamp(1, cap);
        let mut concealed = Vec::with_capacity(len);
        for sample in self.last_good_frame.iter_mut().take(len) {
            *sample = ((*sample as i32 * 3) / 4) as i16;
            concealed.push(*sample);
        }
        if len < cap {
            self.last_good_frame.rotate_left(len);
        }
        if self.config.frame_samples >= 16 {
            let fade_len = (len.min(self.config.frame_samples) / 8).min(32);
            crossfade_head(&mut concealed, prev_sample, fade_len);
        }
        concealed
    }

    fn record_clean_pop(&mut self) {
        if self.underrun_floor_frames > self.config.min_depth_frames {
            self.underrun_free_pops = self.underrun_free_pops.saturating_add(1);
            if self.underrun_free_pops >= UNDERRUN_FLOOR_DECAY_POPS {
                self.underrun_floor_frames -= 1;
                self.underrun_free_pops = 0;
            }
        }
    }

    fn extend_seq(&mut self, seq: u16) -> u32 {
        let highest_low16 = (self.highest_ext_seq & 0xffff) as u16;
        let diff = seq.wrapping_sub(highest_low16) as i16;
        if diff >= 0 {
            let candidate = self.highest_ext_seq.saturating_add(u32::from(diff as u16));
            self.highest_ext_seq = candidate;
            candidate
        } else {
            let back = (-i32::from(diff)) as u32;
            self.highest_ext_seq.saturating_sub(back)
        }
    }

    fn advance_skipped_seqs(&mut self) {
        while let Some(&first) = self.skipped_seqs.iter().next() {
            if first < self.next_playout_seq {
                self.skipped_seqs.remove(&first);
            } else if first == self.next_playout_seq {
                self.skipped_seqs.remove(&first);
                self.next_playout_seq = self.next_playout_seq.saturating_add(1);
            } else {
                break;
            }
        }
    }

    /// Marks an RTP sequence number belonging to non-audio signaling (e.g. RFC 4733 DTMF)
    /// so playout advances smoothly across it without triggering packet-loss concealment.
    pub fn mark_non_audio_seq(&mut self, seq: u16) {
        if !self.initialized {
            return;
        }
        let ext_seq = self.extend_seq(seq);
        if ext_seq < self.next_playout_seq || self.frames.contains_key(&ext_seq) {
            return;
        }
        self.skipped_seqs.insert(ext_seq);
        let cap = self.config.max_depth_frames.saturating_mul(16).max(32);
        while self.skipped_seqs.len() > cap {
            if let Some(&oldest) = self.skipped_seqs.iter().next() {
                self.skipped_seqs.remove(&oldest);
            } else {
                break;
            }
        }
    }

    /// Inserts a decoded PCM packet (of any valid `ptime` duration) and adapts target depth using `jitter_samples`.
    pub fn push(&mut self, seq: u16, pcm_frame: Vec<i16>, jitter_samples: u32) {
        if pcm_frame.is_empty() {
            return;
        }
        let frame_samples = self.config.frame_samples.max(1);
        self.nominal_pkt_samples = pcm_frame.len().clamp(1, frame_samples.saturating_mul(6));

        let was_initialized = self.initialized;
        self.update_target_depth(jitter_samples, was_initialized);

        if !was_initialized {
            self.initialized = true;
            // Anchor around 0x0001_0000 so slightly out-of-order negative offsets stay non-negative.
            let anchor = 0x0001_0000u32.saturating_add(u32::from(seq));
            self.highest_ext_seq = anchor;
            self.next_playout_seq = anchor;
            self.insert_frame(anchor, pcm_frame);
            return;
        }

        let ext_seq = self.extend_seq(seq);

        if ext_seq < self.next_playout_seq {
            if !self.primed
                && !self.recovering_from_underrun
                && self.playout_fifo.is_empty()
                && self.next_playout_seq.saturating_sub(ext_seq) <= 16
            {
                self.next_playout_seq = ext_seq;
            } else {
                self.late_drops = self.late_drops.saturating_add(1);
                return;
            }
        }
        if self.frames.contains_key(&ext_seq) {
            self.duplicate_drops = self.duplicate_drops.saturating_add(1);
            return;
        }
        self.skipped_seqs.remove(&ext_seq);

        self.insert_frame(ext_seq, pcm_frame);

        let max_samples = self
            .config
            .max_depth_frames
            .saturating_mul(2)
            .max(4)
            .saturating_mul(frame_samples);
        let max_pkts = self.config.max_depth_frames.saturating_mul(16).max(32);
        while (self.queued_frame_samples > max_samples && self.frames.len() > 1)
            || self.frames.len() > max_pkts
        {
            if let Some(&oldest_seq) = self.frames.keys().next() {
                let _ = self.remove_frame(oldest_seq);
                if oldest_seq >= self.next_playout_seq {
                    self.next_playout_seq = oldest_seq.saturating_add(1);
                }
            } else {
                break;
            }
        }
    }

    /// Pops the next 20 ms (`config.frame_samples`) playout frame, assembling smaller packets (`5`/`10` ms),
    /// slicing larger packets (`30`/`40`/`60` ms), or emitting concealed/buffering audio when needed.
    pub fn pop(&mut self) -> PlayoutFrame {
        let frame_samples = self.config.frame_samples.max(1);
        if !self.initialized {
            self.last_emitted_sample = 0;
            return PlayoutFrame::Buffering(vec![0; frame_samples]);
        }

        if !self.primed {
            let prime_samples = self
                .target_depth_frames
                .saturating_mul(frame_samples)
                .max(self.nominal_pkt_samples);
            if self.total_buffered_samples() < prime_samples {
                self.last_emitted_sample = 0;
                return PlayoutFrame::Buffering(vec![0; frame_samples]);
            }
            self.primed = true;
        }

        self.advance_skipped_seqs();

        // Smoothly shrink sustained excess depth (> target + 2 frames in duration for >= 12 ticks)
        // without clipping finite packet bursts or normal sub-20 ms packet streams.
        let excess_limit_samples = self
            .target_depth_frames
            .saturating_add(2)
            .saturating_mul(frame_samples)
            .max(self.nominal_pkt_samples.saturating_add(frame_samples));
        if self.total_buffered_samples() > excess_limit_samples {
            self.excess_depth_ticks = self.excess_depth_ticks.saturating_add(1);
            if self.excess_depth_ticks >= 12 {
                if let Some(&oldest_seq) = self.frames.keys().next() {
                    let _ = self.remove_frame(oldest_seq);
                    if oldest_seq >= self.next_playout_seq {
                        self.next_playout_seq = oldest_seq.saturating_add(1);
                        self.advance_skipped_seqs();
                    }
                } else if self.playout_fifo.len() > excess_limit_samples {
                    let drop_n = frame_samples.min(self.playout_fifo.len());
                    let _ = self.playout_fifo.drain(..drop_n);
                }
            }
        } else {
            self.excess_depth_ticks = 0;
        }

        // Zero-copy fast path for standard 20 ms (`frame_samples`) packets when `playout_fifo` is empty.
        if self.playout_fifo.is_empty()
            && self
                .frames
                .get(&self.next_playout_seq)
                .is_some_and(|f| f.len() == frame_samples)
        {
            if let Some(mut pcm) = self.remove_frame(self.next_playout_seq) {
                self.next_playout_seq = self.next_playout_seq.saturating_add(1);
                self.last_good_frame.copy_from_slice(&pcm);
                if (self.consecutive_concealed > 0 || self.recovering_from_underrun)
                    && frame_samples >= 16
                {
                    let fade_len = (frame_samples / 8).min(32);
                    crossfade_head(&mut pcm, self.last_emitted_sample, fade_len);
                }
                self.consecutive_concealed = 0;
                self.recovering_from_underrun = false;
                self.last_emitted_sample = *pcm.last().unwrap_or(&0);
                self.record_clean_pop();
                return PlayoutFrame::Normal(pcm);
            }
        }

        // General multi-duration packet assembly path (`5`/`10`/`20`/`30`/`40`/`60`/`120` ms).
        let mut had_real_audio = !self.playout_fifo.is_empty();
        while self.playout_fifo.len() < frame_samples {
            self.advance_skipped_seqs();
            let tail_sample = self
                .playout_fifo
                .back()
                .copied()
                .unwrap_or(self.last_emitted_sample);

            if let Some(mut pcm) = self.remove_frame(self.next_playout_seq) {
                self.next_playout_seq = self.next_playout_seq.saturating_add(1);
                if (self.consecutive_concealed > 0 || self.recovering_from_underrun)
                    && frame_samples >= 16
                {
                    let fade_len = (pcm.len().min(frame_samples) / 8).min(32);
                    crossfade_head(&mut pcm, tail_sample, fade_len);
                }
                self.update_last_good_tail(&pcm);
                self.consecutive_concealed = 0;
                self.recovering_from_underrun = false;
                self.playout_fifo.extend(pcm);
                had_real_audio = true;
            } else if !self.frames.is_empty() {
                // True missing packet (`next_playout_seq` absent while newer packets are queued):
                // conceal exactly one nominal packet duration so timeline phase stays locked.
                self.next_playout_seq = self.next_playout_seq.saturating_add(1);
                self.consecutive_concealed = self.consecutive_concealed.saturating_add(1);
                self.concealed_frames = self.concealed_frames.saturating_add(1);
                let plc = self.synthesize_missing_plc(self.nominal_pkt_samples, tail_sample);
                self.playout_fifo.extend(plc);
            } else {
                break;
            }
        }

        if self.playout_fifo.len() >= frame_samples {
            let out: Vec<i16> = self.playout_fifo.drain(..frame_samples).collect();
            self.last_emitted_sample = *out.last().unwrap_or(&0);
            if had_real_audio {
                self.record_clean_pop();
                return PlayoutFrame::Normal(out);
            }
            return PlayoutFrame::Concealed(out);
        }

        // Partial sub-frame left in `playout_fifo` when `self.frames` ran dry: emit real prefix
        // tapered smoothly to zero without advancing `next_playout_seq`.
        if !self.playout_fifo.is_empty() {
            let max_depth = self
                .config
                .max_depth_frames
                .max(self.config.min_depth_frames)
                .max(1);
            self.underrun_floor_frames = (self.underrun_floor_frames + 1).min(max_depth);
            self.target_depth_frames = self.target_depth_frames.max(self.underrun_floor_frames);
            self.underrun_free_pops = 0;
            self.low_jitter_packets = 0;
            self.consecutive_concealed = self.consecutive_concealed.saturating_add(1);
            self.concealed_frames = self.concealed_frames.saturating_add(1);
            self.recovering_from_underrun = true;

            let mut out: Vec<i16> = Vec::with_capacity(frame_samples);
            out.extend(self.playout_fifo.drain(..));
            let anchor = i32::from(*out.last().unwrap_or(&0));
            let pad = frame_samples - out.len();
            let denom = pad.max(1) as i32;
            for idx in 0..pad {
                let remain = (denom - 1 - (idx as i32)).max(0);
                out.push(((anchor * remain) / denom) as i16);
            }
            self.last_emitted_sample = *out.last().unwrap_or(&0);
            return if had_real_audio {
                PlayoutFrame::Normal(out)
            } else {
                PlayoutFrame::Concealed(out)
            };
        }

        // Distinguish true missing/out-of-order packets (`!self.frames.is_empty()`) from empty-buffer
        // starvation / clock skew (`self.frames.is_empty()`). Never advance `next_playout_seq` here!
        if self.consecutive_concealed >= 1 {
            self.primed = false;
            self.recovering_from_underrun = true;
            self.last_emitted_sample = 0;
            return PlayoutFrame::Buffering(vec![0; frame_samples]);
        }

        let max_depth = self
            .config
            .max_depth_frames
            .max(self.config.min_depth_frames)
            .max(1);
        self.underrun_floor_frames = (self.underrun_floor_frames + 1).min(max_depth);
        self.target_depth_frames = self.target_depth_frames.max(self.underrun_floor_frames);
        self.underrun_free_pops = 0;
        self.low_jitter_packets = 0;

        self.consecutive_concealed = self.consecutive_concealed.saturating_add(1);
        self.concealed_frames = self.concealed_frames.saturating_add(1);

        // Smoothly taper `last_good_frame` from 3/4 amplitude linearly down to 0 across the single 20 ms
        // slip frame so `last_emitted_sample` reaches 0 without 50 Hz frame-clone buzz or step clicks.
        let n = self.last_good_frame.len();
        let mut concealed = Vec::with_capacity(n);
        let denom = n.max(1) as i32;
        for (idx, sample) in self.last_good_frame.iter_mut().enumerate() {
            let remain = (denom - 1 - (idx as i32)).max(0);
            let tapered = ((*sample as i32 * 3 * remain) / (4 * denom)) as i16;
            *sample = tapered;
            concealed.push(tapered);
        }
        if frame_samples >= 16 {
            let fade_len = (frame_samples / 8).min(32);
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

    /// Resets sequence tracking and buffered frames while preserving lifetime diagnostic counters.
    ///
    /// Used when the remote RTP stream changes SSRC mid-call (e.g., PBX bridge or transfer).
    pub fn reset(&mut self) {
        let frame_samples = self.config.frame_samples.max(1);
        let max_depth = self
            .config
            .max_depth_frames
            .max(self.config.min_depth_frames)
            .max(1);
        self.frames.clear();
        self.queued_frame_samples = 0;
        self.playout_fifo.clear();
        self.nominal_pkt_samples = frame_samples;
        self.skipped_seqs.clear();
        self.primed = false;
        self.initialized = false;
        self.recovering_from_underrun = false;
        self.highest_ext_seq = 0;
        self.next_playout_seq = 0;
        self.target_depth_frames = self
            .config
            .initial_depth_frames
            .clamp(self.config.min_depth_frames, max_depth);
        self.underrun_floor_frames = self.config.min_depth_frames;
        self.underrun_free_pops = 0;
        self.low_jitter_packets = 0;
        self.excess_depth_ticks = 0;
        self.last_good_frame.fill(0);
        self.last_emitted_sample = 0;
        self.consecutive_concealed = 0;
    }

    fn update_target_depth(&mut self, jitter_samples: u32, was_initialized: bool) {
        let frame_samples = self.config.frame_samples.max(1);
        let max_depth = self
            .config
            .max_depth_frames
            .max(self.config.min_depth_frames)
            .max(1);
        let jitter_frames = (jitter_samples as usize).div_ceil(frame_samples);
        let floor = self
            .config
            .min_depth_frames
            .max(self.underrun_floor_frames)
            .min(max_depth);
        let desired = (jitter_frames + 1).clamp(floor, max_depth);

        if desired > self.target_depth_frames {
            self.target_depth_frames = desired;
            self.low_jitter_packets = 0;
        } else if was_initialized && desired < self.target_depth_frames {
            let init_clamped = self.config.initial_depth_frames.clamp(floor, max_depth);
            if self.target_depth_frames > init_clamped {
                self.target_depth_frames -= 1;
                self.low_jitter_packets = 0;
            } else {
                self.low_jitter_packets = self.low_jitter_packets.saturating_add(1);
                if self.low_jitter_packets >= SUB_INITIAL_SHRINK_PACKETS {
                    self.target_depth_frames -= 1;
                    self.low_jitter_packets = 0;
                }
            }
        } else {
            self.low_jitter_packets = 0;
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

    #[test]
    fn skips_non_audio_dtmf_seqs_and_drains_excess_depth_smoothly() {
        let cfg = JitterBufferConfig {
            min_depth_frames: 2,
            max_depth_frames: 12,
            initial_depth_frames: 2,
            frame_samples: 4,
        };
        let mut jb = AdaptiveJitterBuffer::new(cfg);

        jb.push(10, vec![10; 4], 0);
        jb.mark_non_audio_seq(11); // DTMF packet between audio frames 10 and 12
        jb.push(12, vec![12; 4], 0);

        assert_eq!(jb.pop(), PlayoutFrame::Normal(vec![10; 4]));
        assert_eq!(jb.pop(), PlayoutFrame::Normal(vec![12; 4]));
        assert_eq!(jb.counters().2, 0, "DTMF seq must not trigger PLC");

        // Push a burst of 8 consecutive frames, then sustain 1:1 push/pop cadence so sustained
        // excess depth above target (2) + 2 = 4 shrinks smoothly without dropping transient bursts.
        for s in 13u16..=20 {
            jb.push(s, vec![s as i16; 4], 0);
        }
        let mut drained = Vec::new();
        for s in 21u16..=40 {
            jb.push(s, vec![s as i16; 4], 0);
            drained.push(jb.pop());
        }
        // After draining to target + 2 = 4, popping the rest must leave <= 4 remaining buffered frames.
        let mut remaining = 0usize;
        while matches!(jb.pop(), PlayoutFrame::Normal(_)) {
            remaining += 1;
        }
        assert!(
            remaining <= 4,
            "expected sustained excess depth to shrink to <= 4 frames, left {remaining}"
        );
        assert!(drained.iter().all(|f| matches!(f, PlayoutFrame::Normal(_))));
    }

    #[test]
    fn underrun_holds_playout_seq_without_late_drop_death_spiral() {
        let cfg = JitterBufferConfig {
            min_depth_frames: 2,
            max_depth_frames: 8,
            initial_depth_frames: 2,
            frame_samples: 160,
        };
        let mut jb = AdaptiveJitterBuffer::new(cfg);

        // Prime with packets 100 and 101, then drain both so `frames` becomes empty.
        jb.push(100, vec![4000; 160], 0);
        jb.push(101, vec![4000; 160], 0);
        assert!(matches!(jb.pop(), PlayoutFrame::Normal(_)));
        assert!(matches!(jb.pop(), PlayoutFrame::Normal(_)));

        // Packet 102 arrives 1 ms AFTER `pop()` (buffer underrun due to sender clock skew / scheduling jitter).
        let slip = jb.pop();
        assert!(matches!(slip, PlayoutFrame::Concealed(_)));
        assert_eq!(
            *slip.samples().last().unwrap(),
            0,
            "underrun slip frame must taper smoothly to zero"
        );
        assert_eq!(
            jb.target_depth_frames(),
            3,
            "underrun must raise target depth floor by +1 frame"
        );

        // Packets 102..=105 arrive immediately after — ZERO packets may be discarded as `late_drops`!
        for seq in 102u16..=105 {
            jb.push(seq, vec![2000; 160], 0);
            let out = jb.pop();
            assert!(
                matches!(out, PlayoutFrame::Normal(_)),
                "expected packet {seq} to play normally without PLC spiral, got {out:?}"
            );
        }
        assert_eq!(
            jb.counters(),
            (0, 0, 1),
            "expected zero late drops and exactly one slip concealment"
        );
    }

    #[test]
    fn sustained_dtx_pause_tapers_once_and_reprimes_without_robotic_buzz() {
        let cfg = JitterBufferConfig {
            min_depth_frames: 2,
            max_depth_frames: 8,
            initial_depth_frames: 3,
            frame_samples: 160,
        };
        let mut jb = AdaptiveJitterBuffer::new(cfg);

        // Initial packet with jitter=0 must preserve `initial_depth_frames = 3` during cold start.
        jb.push(1, vec![6000; 160], 0);
        assert_eq!(jb.target_depth_frames(), 3);
        jb.push(2, vec![6000; 160], 0);
        jb.push(3, vec![6000; 160], 0);

        assert!(matches!(jb.pop(), PlayoutFrame::Normal(_)));
        assert!(matches!(jb.pop(), PlayoutFrame::Normal(_)));
        assert!(matches!(jb.pop(), PlayoutFrame::Normal(_)));

        // Sender enters silent DTX pause: first empty pop tapers smoothly, second enters Buffering immediately
        // instead of repeating 4 robotic 50 Hz clones!
        let f_taper = jb.pop();
        let f_buf = jb.pop();
        assert!(matches!(f_taper, PlayoutFrame::Concealed(_)));
        assert!(matches!(f_buf, PlayoutFrame::Buffering(_)));
        assert_eq!(jb.counters().2, 1);
    }

    #[test]
    fn assembles_10ms_30ms_40ms_and_midcall_ptime_transitions_without_packet_drops() {
        let cfg = JitterBufferConfig {
            min_depth_frames: 2,
            max_depth_frames: 12,
            initial_depth_frames: 3,
            frame_samples: 960, // 20 ms @ 48 kHz
        };
        let mut jb = AdaptiveJitterBuffer::new(cfg);

        // 1. Prime with six 10 ms packets (6 * 480 = 2880 samples = 60 ms), out-of-order 1 & 0.
        jb.push(101, vec![101; 480], 0);
        jb.push(100, vec![100; 480], 0);
        for seq in 102u16..106 {
            jb.push(seq, vec![seq as i16; 480], 0);
        }

        let first = jb.pop();
        assert!(matches!(first, PlayoutFrame::Normal(_)));
        assert_eq!(first.samples().len(), 960);
        assert_eq!(&first.samples()[..480], &[100i16; 480]);
        assert_eq!(&first.samples()[480..], &[101i16; 480]);

        // 2. Sustain 200 packets of 10 ms (2.0 s at 2 packets per 20 ms pop): zero excess-depth drops!
        let mut next_seq = 106u16;
        for tick in 0..100 {
            jb.push(next_seq, vec![500; 480], 0);
            jb.push(next_seq + 1, vec![600; 480], 0);
            next_seq += 2;
            let frame = jb.pop();
            assert!(matches!(frame, PlayoutFrame::Normal(_)));
            assert_eq!(frame.samples().len(), 960);
            // First 2 pops drain queued prime pairs (102/103, 104/105); remaining 98 pops emit 500/600!
            if tick >= 2 {
                assert_eq!(&frame.samples()[..480], &[500i16; 480]);
                assert_eq!(&frame.samples()[480..], &[600i16; 480]);
            }
        }
        assert_eq!(jb.counters(), (0, 0, 0));

        // 3. Switch mid-call on the same SSRC to 40 ms packets (1920 samples -> 2 pops of 960).
        jb.push(next_seq, vec![900; 1920], 0);
        next_seq += 1;
        jb.push(next_seq, vec![1100; 1920], 0);
        // Drain remaining queued 10 ms pairs + the two 40 ms packets cleanly.
        let mut normal_pops = 0usize;
        while let PlayoutFrame::Normal(samples) = jb.pop() {
            assert_eq!(samples.len(), 960);
            normal_pops += 1;
            if normal_pops > 10 {
                break;
            }
        }
        assert_eq!(
            normal_pops, 6,
            "expected 2 remaining 20ms pairs + 4 halves of 40ms"
        );
    }
}
