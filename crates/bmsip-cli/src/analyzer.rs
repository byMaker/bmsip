//! MODULE_CONTRACT: Pure-Rust DSP audio quality analyzer measuring dBFS levels, dropouts, phase clicks, frequency accuracy, and quadrature SNR on WAV recordings.
//! INVARIANTS: `#![forbid(unsafe_code)]`; zero external DSP crates; safe on empty, silent, or clipped PCM buffers without panics or division by zero.
//! RFC_REFS: ITU-T P.56 (active speech levels), RFC 3551 (20 ms framing).

use bmsip_engine::bmsip_media::WavPcm16;
use std::f64::consts::PI;

const MIN_DBFS: f64 = -120.0;

/// Quantitative DSP inspection summary for a mono 16-bit PCM recording.
#[derive(Debug, Clone, PartialEq)]
pub struct AudioQualityReport {
    pub sample_rate_hz: u32,
    pub total_samples: usize,
    pub duration_ms: u64,
    pub frame_samples: usize,
    pub total_frames: usize,
    pub active_frames: usize,
    pub initial_latency_ms: u64,
    pub mid_stream_dropouts: usize,
    pub boundary_clicks: usize,
    pub max_boundary_jump: i32,
    pub rms_pcm: u32,
    pub rms_dbfs: f64,
    pub peak_pcm: u32,
    pub peak_dbfs: f64,
    pub dc_offset: f64,
    pub clipped_samples: usize,
    pub detected_freq_hz: f64,
    pub target_tone_hz: Option<u32>,
    pub snr_db: Option<f64>,
}

impl AudioQualityReport {
    /// Formats a multi-line inspection report suitable for CLI `analyze`.
    pub fn format_multiline(&self) -> String {
        let freq_str = if self.detected_freq_hz > 0.0 {
            format!("{:.1} Hz", self.detected_freq_hz)
        } else {
            "n/a".to_string()
        };
        let snr_str = self
            .snr_db
            .map_or_else(|| "n/a".to_string(), |s| format!("{s:.1} dB"));
        format!(
            "Audio Quality Report:\n  \
             Sample rate:        {} Hz ({} samples, {} ms)\n  \
             20 ms frames:       {} total / {} active\n  \
             Initial latency:    {} ms\n  \
             Levels:             RMS {} ({:.1} dBFS), Peak {} ({:.1} dBFS)\n  \
             DC offset / clips:  {:.1} / {} samples\n  \
             Dropouts / clicks:  {} mid-stream dropouts, {} boundary clicks (max jump {})\n  \
             Frequency / SNR:    {} (target {:?}), SNR {}",
            self.sample_rate_hz,
            self.total_samples,
            self.duration_ms,
            self.total_frames,
            self.active_frames,
            self.initial_latency_ms,
            self.rms_pcm,
            self.rms_dbfs,
            self.peak_pcm,
            self.peak_dbfs,
            self.dc_offset,
            self.clipped_samples,
            self.mid_stream_dropouts,
            self.boundary_clicks,
            self.max_boundary_jump,
            freq_str,
            self.target_tone_hz,
            snr_str
        )
    }

    /// Formats a compact single-line summary appended to `call` and `listen` runs.
    pub fn format_oneliner(&self) -> String {
        let snr_part = self
            .snr_db
            .map_or_else(String::new, |s| format!(", SNR={s:.1}dB"));
        let freq_part = if self.detected_freq_hz > 0.0 {
            format!(", freq={:.1}Hz", self.detected_freq_hz)
        } else {
            String::new()
        };
        format!(
            "Audio DSP: rate={}Hz, RMS={:.1}dBFS, peak={:.1}dBFS, latency={}ms, dropouts={}, clicks={}{}{}",
            self.sample_rate_hz,
            self.rms_dbfs,
            self.peak_dbfs,
            self.initial_latency_ms,
            self.mid_stream_dropouts,
            self.boundary_clicks,
            freq_part,
            snr_part
        )
    }
}

/// Analyzes a mono [`WavPcm16`] clip and optional target sine frequency into an [`AudioQualityReport`].
pub fn analyze_wav(wav: &WavPcm16, target_tone_hz: Option<u32>) -> AudioQualityReport {
    let sample_rate_hz = wav.sample_rate.max(1);
    let total_samples = wav.samples.len();
    let frame_samples = ((sample_rate_hz as usize) / 50).max(1);
    let duration_ms = (total_samples as u64).saturating_mul(1000) / u64::from(sample_rate_hz);

    if wav.samples.is_empty() {
        return AudioQualityReport {
            sample_rate_hz,
            total_samples: 0,
            duration_ms: 0,
            frame_samples,
            total_frames: 0,
            active_frames: 0,
            initial_latency_ms: 0,
            mid_stream_dropouts: 0,
            boundary_clicks: 0,
            max_boundary_jump: 0,
            rms_pcm: 0,
            rms_dbfs: MIN_DBFS,
            peak_pcm: 0,
            peak_dbfs: MIN_DBFS,
            dc_offset: 0.0,
            clipped_samples: 0,
            detected_freq_hz: 0.0,
            target_tone_hz,
            snr_db: None,
        };
    }

    let mut sum_sq: u128 = 0;
    let mut sum_signed: i64 = 0;
    let mut peak_pcm: u32 = 0;
    let mut clipped_samples: usize = 0;

    for &s in &wav.samples {
        let abs = i32::from(s).abs();
        sum_sq += u128::from(abs as u64) * u128::from(abs as u64);
        sum_signed += i64::from(s);
        peak_pcm = peak_pcm.max(abs as u32);
        if abs >= 32_000 {
            clipped_samples += 1;
        }
    }

    let rms_float = ((sum_sq as f64) / (total_samples as f64)).sqrt();
    let rms_pcm = rms_float.round() as u32;
    let rms_dbfs = to_dbfs(rms_float);
    let peak_dbfs = to_dbfs(f64::from(peak_pcm));
    let dc_offset = (sum_signed as f64) / (total_samples as f64);

    let frames: Vec<&[i16]> = wav.samples.chunks(frame_samples).collect();
    let total_frames = frames.len();
    let active_flags: Vec<bool> = frames.iter().map(|f| is_active_frame(f)).collect();
    let active_frames = active_flags.iter().filter(|&&a| a).count();

    let first_active = active_flags.iter().position(|&a| a);
    let last_active = active_flags.iter().rposition(|&a| a);
    let initial_latency_ms = first_active.map_or(duration_ms, |idx| (idx as u64) * 20);

    let mid_stream_dropouts = match (first_active, last_active) {
        (Some(first), Some(last)) if last > first + 1 => active_flags[(first + 1)..last]
            .iter()
            .filter(|&&a| !a)
            .count(),
        _ => 0,
    };

    let (boundary_clicks, max_boundary_jump) = count_boundary_clicks(&frames, &active_flags);

    let eval_range = match (first_active, last_active) {
        (Some(first), Some(last)) if last > first + 1 => (first + 1)..(last + 1),
        (Some(first), Some(last)) => first..(last + 1),
        _ => 0..0,
    };

    let detected_freq_hz =
        estimate_frequency_hz(sample_rate_hz, &frames, &active_flags, eval_range.clone());
    let eval_freq = target_tone_hz
        .map(f64::from)
        .filter(|&f| f > 0.0)
        .unwrap_or(detected_freq_hz);
    let snr_db = compute_quadrature_snr_db(
        sample_rate_hz,
        &frames,
        &active_flags,
        eval_range,
        eval_freq,
    );

    AudioQualityReport {
        sample_rate_hz,
        total_samples,
        duration_ms,
        frame_samples,
        total_frames,
        active_frames,
        initial_latency_ms,
        mid_stream_dropouts,
        boundary_clicks,
        max_boundary_jump,
        rms_pcm,
        rms_dbfs,
        peak_pcm,
        peak_dbfs,
        dc_offset,
        clipped_samples,
        detected_freq_hz,
        target_tone_hz,
        snr_db,
    }
}

fn to_dbfs(amp: f64) -> f64 {
    if amp <= 1e-6 {
        MIN_DBFS
    } else {
        (20.0 * (amp / 32_767.0).log10()).max(MIN_DBFS)
    }
}

fn is_active_frame(frame: &[i16]) -> bool {
    if frame.is_empty() {
        return false;
    }
    let mut sum_sq: u64 = 0;
    let mut peak: i32 = 0;
    for &s in frame {
        let abs = i32::from(s).abs();
        sum_sq += (abs as u64) * (abs as u64);
        peak = peak.max(abs);
    }
    let rms = ((sum_sq as f64) / (frame.len() as f64)).sqrt();
    rms > 15.0 || peak > 40
}

fn max_internal_step(frame: &[i16]) -> i32 {
    frame
        .windows(2)
        .map(|w| (i32::from(w[1]) - i32::from(w[0])).abs())
        .max()
        .unwrap_or(0)
}

fn count_boundary_clicks(frames: &[&[i16]], active_flags: &[bool]) -> (usize, i32) {
    let mut clicks = 0usize;
    let mut max_jump = 0i32;

    for idx in 1..frames.len() {
        if !active_flags[idx - 1] || !active_flags[idx] {
            continue;
        }
        let prev = frames[idx - 1];
        let curr = frames[idx];
        let (Some(&prev_last), Some(&curr_first)) = (prev.last(), curr.first()) else {
            continue;
        };
        let jump = (i32::from(curr_first) - i32::from(prev_last)).abs();
        max_jump = max_jump.max(jump);
        let max_step = max_internal_step(prev).max(max_internal_step(curr));
        if jump > (max_step.saturating_mul(3)).max(1500) {
            clicks += 1;
        }
    }

    (clicks, max_jump)
}

fn estimate_frequency_hz(
    sample_rate_hz: u32,
    frames: &[&[i16]],
    active_flags: &[bool],
    eval_range: std::ops::Range<usize>,
) -> f64 {
    if eval_range.is_empty() {
        return 0.0;
    }

    let mut flat_samples: Vec<f64> = Vec::new();
    for idx in eval_range {
        if let (Some(frame), Some(&true)) = (frames.get(idx), active_flags.get(idx)) {
            flat_samples.extend(frame.iter().map(|&s| f64::from(s)));
        }
    }
    if flat_samples.len() < 4 {
        return 0.0;
    }

    let mean = flat_samples.iter().sum::<f64>() / (flat_samples.len() as f64);
    let mut crossings: Vec<f64> = Vec::new();
    for i in 1..flat_samples.len() {
        let s0 = flat_samples[i - 1] - mean;
        let s1 = flat_samples[i] - mean;
        if s0 <= 0.0 && s1 > 0.0 {
            let frac = (-s0) / (s1 - s0);
            crossings.push(((i - 1) as f64) + frac);
        }
    }

    if crossings.len() < 2 {
        return 0.0;
    }
    let span = crossings[crossings.len() - 1] - crossings[0];
    if span <= 0.0 {
        return 0.0;
    }
    f64::from(sample_rate_hz) * ((crossings.len() - 1) as f64) / span
}

fn compute_quadrature_snr_db(
    sample_rate_hz: u32,
    frames: &[&[i16]],
    active_flags: &[bool],
    eval_range: std::ops::Range<usize>,
    freq_hz: f64,
) -> Option<f64> {
    if eval_range.is_empty() || freq_hz <= 20.0 || freq_hz >= f64::from(sample_rate_hz) * 0.49 {
        return None;
    }

    let omega = 2.0 * PI * freq_hz / f64::from(sample_rate_hz);
    let mut total_sig = 0.0f64;
    let mut total_err = 0.0f64;
    let mut evaluated = 0usize;

    for idx in eval_range {
        if !active_flags.get(idx).copied().unwrap_or(false) {
            continue;
        }
        let Some(frame) = frames.get(idx) else {
            continue;
        };
        if frame.len() < 16 {
            continue;
        }

        let mut acc = 0.0f64;
        let mut ass = 0.0f64;
        let mut acs = 0.0f64;
        let mut bc = 0.0f64;
        let mut bs = 0.0f64;

        for (n, &sample) in frame.iter().enumerate() {
            let phase = omega * (n as f64);
            let c = phase.cos();
            let s = phase.sin();
            let x = f64::from(sample);
            acc += c * c;
            ass += s * s;
            acs += c * s;
            bc += x * c;
            bs += x * s;
        }

        let det = acc * ass - acs * acs;
        if det.abs() < 1e-9 {
            continue;
        }
        let coef_c = (bc * ass - bs * acs) / det;
        let coef_s = (acc * bs - acs * bc) / det;

        for (n, &sample) in frame.iter().enumerate() {
            let phase = omega * (n as f64);
            let est = coef_c * phase.cos() + coef_s * phase.sin();
            let err = f64::from(sample) - est;
            total_sig += est * est;
            total_err += err * err;
        }
        evaluated += 1;
    }

    if evaluated == 0 || total_sig <= 0.0 {
        return None;
    }
    Some(10.0 * (total_sig / total_err.max(1e-9)).log10())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_sine_wave_reports_accurate_frequency_high_snr_and_zero_glitches() {
        let wav = WavPcm16::generate_sine_wave(48_000, 440, 600, 12_000);
        let report = analyze_wav(&wav, Some(440));
        assert_eq!(report.sample_rate_hz, 48_000);
        assert_eq!(report.total_frames, 30);
        assert_eq!(report.active_frames, 30);
        assert_eq!(report.initial_latency_ms, 0);
        assert_eq!(report.mid_stream_dropouts, 0);
        assert_eq!(report.boundary_clicks, 0);
        assert!(
            (report.detected_freq_hz - 440.0).abs() <= 5.0,
            "unexpected freq: {}",
            report.detected_freq_hz
        );
        assert!(
            report.snr_db.expect("SNR present") > 35.0,
            "expected high SNR, got {:?}",
            report.snr_db
        );
    }

    #[test]
    fn detects_injected_mid_stream_zero_dropout() {
        let mut wav = WavPcm16::generate_sine_wave(8_000, 440, 400, 12_000);
        // Zero out 20 ms frame #10 (samples 1600..1760) in the middle of active audio.
        wav.samples[1600..1760].fill(0);
        let report = analyze_wav(&wav, Some(440));
        assert_eq!(report.mid_stream_dropouts, 1);
    }
}
