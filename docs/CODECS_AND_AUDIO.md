# Codecs, Audio Bridge & Custom Codec Plugins

This document describes `bmsip`'s audio pipeline (`bmsip-media` and `bmsip-engine`), built-in codecs, RFC 4733 DTMF signaling, and how to register external custom codecs at runtime.

---

## 1. Built-In Audio Codecs ("Golden Trio")

| Codec | Module | Audio Rate | RTP Clock Rate | 20 ms Frame Size | Bitrate | Key Use Case |
|---|---|---|---|---|---|---|
| **Opus** | `bmsip-engine::opus_native` (`libopus`) + `bmsip-media::opus` | `48000 Hz` | `48000 Hz` (`960` ticks) | `960` PCM samples (`~60–160 B`) | ~64 kbps CBR/VBR | Fullband HD softphones, mobile VoIP, WebRTC interop |
| **G.722** | `bmsip-media::g722` (pure Safe Rust) | `16000 Hz` | `8000 Hz` (`160` ticks)¹ | `320` PCM samples (`160 B`) | `64 kbps` | Hardware desk IP phones (Yealink/Cisco/Polycom) & HD PBXs |
| **PCMU** | `bmsip-media::codec` (pure Safe Rust) | `8000 Hz` | `8000 Hz` (`160` ticks) | `160` PCM samples (`160 B`) | `64 kbps` | Universal narrowband fallback (North America / trunks) |
| **PCMA** | `bmsip-media::codec` (pure Safe Rust) | `8000 Hz` | `8000 Hz` (`160` ticks) | `160` PCM samples (`160 B`) | `64 kbps` | Universal narrowband fallback (Europe / E1 PSTN) |

> ¹ **RFC 3551 §4.5.2 Quirk (Handled Automatically):** ITU-T G.722 samples audio at `16000 Hz` (`320` PCM samples per 20 ms frame), but for historical reasons RFC 3551 mandates an RTP clock rate of **`8000 Hz`** (`160` timestamp ticks per 20 ms packet) and static payload type `9`. `MediaSession` and `G722Codec` separate `rtp_clock_rate_hz = 8000` from `pcm_sample_rate_hz = 16000` automatically.

### 1.1 Opus (`LibOpusCodec` & `BuiltInOpusCodec`)

- **`bmsip-engine::LibOpusCodec`** ([`crates/bmsip-engine/src/opus_native.rs`](../crates/bmsip-engine/src/opus_native.rs)): Links system `libopus` (`build.rs`) and implements `OpusCodecBackend` at `48000 Hz` mono using `OPUS_APPLICATION_VOIP`, `64 kbps` bitrate, complexity `8`, and optional in-band FEC (`OPUS_SET_INBAND_FEC(1)`). `SipEngine` probes `LibOpusCodec` at startup and strips `opus` from advertised SDP codecs if native `libopus` initialization fails, rather than sending placeholder bytes on the wire.
- **`bmsip-media::BuiltInOpusCodec` / `CodecRegistry::with_builtin_codecs()`** ([`crates/bmsip-media/src/opus.rs`](../crates/bmsip-media/src/opus.rs)): Pure-Rust `#![forbid(unsafe_code)]` RFC 6716 TOC packet helper (`OpusToc`) and SDP `fmtp` parser (`OpusFmtp`) retained strictly for pure-Rust `bmsip-media` unit tests; `CodecRegistry::with_builtin_codecs()` registers only standard-compliant pure-Rust `G722`, `PCMU`, and `PCMA`.
- **`condition_mic_frame` (`bmsip-media::opus`)**: Pre-conditions raw microphone PCM frames using a **frame-level peak noise gate** (preventing zero-crossing crossover distortion), fixed-point `Q8` gain scaling, and rational soft-knee peak limiting within `[-32000, 32000]`.

### 1.2 Pure-Rust ITU-T G.722 (`bmsip-media::g722`)

[`crates/bmsip-media/src/g722.rs`](../crates/bmsip-media/src/g722.rs) implements Mode 1 (64 kbps) ITU-T G.722 completely in Safe Rust (`#![forbid(unsafe_code)]`) with zero external crates:

- **24-Tap QMF Analysis/Synthesis Bank:** Splits `16 kHz` audio into `0–4 kHz` lower and `4–8 kHz` upper subbands cleanly with unity gain.
- **SB-ADPCM Predictor (`G722Band::block4`):** 2-pole / 6-zero adaptive ARMA predictor + 6-bit lower / 2-bit upper quantizer tables matching ITU-T G.722 and `codec_g722.so` / `mod_spandsp`.
- **Anti-Aliasing FIR Resamplers & Rate-Explicit `StreamResampler`:** Symmetric triangular low-pass FIR filters (`11`-tap for `48 -> 8 kHz`, `5`-tap for `48 -> 16 kHz`, `3`-tap `[1, 2, 1]/4` for `16 -> 8 kHz`) plus stateful rate-explicit `StreamResampler::resample_by_rate` (supporting `8`/`16`/`48` kHz and arbitrary custom rates across any `2.5`–`120` ms packet duration without confusing `10 ms @ 16 kHz` with `20 ms @ 8 kHz`).

---

## 2. DTMF Signaling (`RFC 4733` & `RFC 2976`) & Comfort Noise (`RFC 3389`)

- **Dual Clock Rates & Duration Scaling (RFC 4733):** `RtpCodec::telephone_event(101)` (`8000 Hz`, paired with G.711/G.722) and `RtpCodec::telephone_event_48k(102)` (`48000 Hz`, paired with Opus for strict servers like FreeSWITCH `mod_sofia`).
- `SipEngine` automatically selects both the matching payload type and exact RTP clock rate (`MediaSession::with_dtmf_clock_rate`), scaling 100 ms RFC 4733 tone durations to `800` ticks at `8000 Hz` or `4800` ticks at `48000 Hz`.
- **Paced Transmission:** `DtmfSender` generates the 20 ms RFC 4733 event progression + 3 redundant end (`E=1`) packets, which `SipEngine::pump_media_tick` paces at 1 packet per 20 ms frame after the initial audio packets establish SSRC/clock baseline.
- **Legacy SIP `INFO` DTMF (RFC 2976):** `EngineCommand::SendInfoDtmf` / `UserAgent::send_info_dtmf` transmits `application/dtmf-relay` (`Signal=<digit>\r\nDuration=<ms>`); inbound `application/dtmf-relay` and `application/dtmf` requests emit the same unified `EngineEvent::DtmfReceived`.
- **Deduplicating Reception:** `DtmfDetector` emits `EngineEvent::DtmfReceived { call_id, digit }` once per key press and resets automatically if the remote RTP SSRC changes mid-call.
- **Comfort Noise (`CN`, PT 13, RFC 3389):** `RtpCodec::cn()` negotiates static payload type `13` (`8000 Hz`); `ComfortNoisePacket` encodes `-dBov` SID levels (`MediaSession::encode_comfort_noise_frame` / `build_comfort_noise_packet`), and inbound SID frames trigger shaped background noise synthesis (`PlayoutFrame::ComfortNoise`) across DTX/VAD gaps until voice RTP resumes.

---

## 3. Adaptive Jitter Buffer & Hardware-Agnostic `AudioPort`

### 3.1 `AudioPort` (`bmsip-engine::audio`)

`AudioPort` exchanges 20 ms mono `i16` frames every `MEDIA_TICK_MS = 20`:

- `sample_rate_hz(&self) -> u32`: declares `8000` (`160` samples), `16000` (`320` samples), or `48000` (`960` samples).
- `capture_frame_20ms(&mut self) -> Vec<i16>`: non-blocking mic/WAV frame supply.
- `playout_20ms(&mut self, samples: &[i16])`: non-blocking decoded speaker/WAV frame sink.

Built-in adapters: `NullAudioPort`, `WavAudioPort`/`WavAudioHandle` (supports `8`/`16`/`48` kHz WAV clips with optional/capped RX recording via `new_with_recording` and `with_max_recorded_samples`), `PcmQueueAudioPort`/`PcmAudioHandle` (configurable `8`/`16`/`48` kHz via `new_with_sample_rate`), and `LiveLinuxAudioPort` (`bmsip-cli`).

### 3.2 `AdaptiveJitterBuffer` (`bmsip-media::jitter`)

- **Out-of-Order Reordering, Variable-`ptime` Framing, Non-Audio Sequence Skipping & Mid-Call SSRC Changes:** Handles 16-bit RTP sequence rollover (RFC 3550 §5.1), reorders arbitrary-duration RTP packets (`2.5`–`120` ms, e.g., `10 ms` Asterisk transcoded G.722, `30`/`40` ms trunks, or `60`/`120` ms Opus) in true sequence space while assembling exact `20 ms` (`frame_samples`) playout frames via `playout_fifo`, resets cleanly on RFC 3550 Appendix A.1 2-packet sequence resync (`SeqStatus::Resynced`), skips non-audio RTP sequence numbers (`mark_non_audio_seq`, e.g., RFC 4733 DTMF) without synthesizing false PLC frames, and resets sequence/jitter state when legitimate mid-call SSRC changes occur.
- **Dynamic Depth Adaptation, Underrun Floor & Excess-Depth Shrinking:** Preserves `initial_depth_frames` across cold-start `jitter = 0` packets (`50`-packet sub-initial shrink window), scales buffered target depth between `[min_depth_frames, max_depth_frames]` using RFC 3550 jitter estimates (`scaled_jitter` adjusted when `AudioPort` sample rate differs from RTP clock rate), raises `underrun_floor_frames` (`+1` frame with `250`-pop / `5 s` decay hysteresis) whenever playout starves, and smoothly drains buffered frames exceeding `target_depth_frames + 2` after transient bursts subside.
- **Missing-Packet PLC vs. Underrun Slip Taper & Boundary Crossfade:** True missing packets (`!frames.is_empty()`) advance `next_playout_seq` and replay an attenuated copy (`3/4` per-frame amplitude decay) of the last good frame; empty-buffer starvation (`frames.is_empty()`, e.g., slight remote clock skew or scheduling jitter) holds `next_playout_seq` so in-flight packets are never discarded as `late_drops` and emits a single linear taper-to-zero slip frame before re-priming (eliminating `50 Hz` multi-frame robotic repetition). Normal, concealed, and post-underrun boundaries crossfade smoothly over up to 32 samples (`(frame_samples / 8).min(32)`) from `last_emitted_sample` to prevent audible phase clicks.

---

## 4. Pluggable External Codec Guide (`AudioCodecPlugin` & `CodecRegistry`)

Applications can register **any custom or proprietary audio codec** (for example `G.729`, `L16`, `AMR-WB`, `GSM`, `Codec2`, or FFI-wrapped C libraries) without modifying `bmsip-core`, `bmsip-media`, or `bmsip-engine`.

### Step 1: Describe and Implement `AudioCodecPlugin`

```rust
use bmsip_media::{AudioCodecDescriptor, AudioCodecPlugin, MediaError};

#[derive(Debug)]
struct CustomL16Plugin {
    descriptor: AudioCodecDescriptor,
}

impl CustomL16Plugin {
    fn descriptor_spec() -> AudioCodecDescriptor {
        // PT 98, SDP "L16/16000", native PCM rate 16000 Hz (320 samples per 20 ms)
        AudioCodecDescriptor::new(98, "L16", 16_000, 16_000)
    }

    fn new() -> Self {
        Self {
            descriptor: Self::descriptor_spec(),
        }
    }
}

impl AudioCodecPlugin for CustomL16Plugin {
    fn descriptor(&self) -> &AudioCodecDescriptor {
        &self.descriptor
    }

    fn encode_native_20ms(&mut self, pcm: &[i16]) -> Result<Vec<u8>, MediaError> {
        let mut out = Vec::with_capacity(pcm.len() * 2);
        for &s in pcm {
            out.extend_from_slice(&s.to_be_bytes());
        }
        Ok(out)
    }

    fn decode_native_20ms(&mut self, payload: &[u8]) -> Result<Vec<i16>, MediaError> {
        let mut out = Vec::with_capacity(payload.len() / 2);
        for chunk in payload.as_chunks::<2>().0 {
            out.push(i16::from_be_bytes([chunk[0], chunk[1]]));
        }
        Ok(out)
    }
}
```

### Step 2: Register with `EngineConfig` Before Spawning `SipEngine`

```rust
use std::sync::Arc;
use bmsip_media::{AudioCodecFactory, FnCodecFactory};

let factory: Arc<dyn AudioCodecFactory> = Arc::new(FnCodecFactory::new(
    CustomL16Plugin::descriptor_spec(),
    || Box::new(CustomL16Plugin::new()),
));

// Registers in codec_registry AND prepends the codec to ua_config.supported_codecs:
engine_cfg.register_custom_codec(factory);
```

### What `bmsip` Handles Automatically

1. **SDP Offer/Answer (`bmsip-core`):** Advertises `a=rtpmap:98 L16/16000` (+ optional `/<channels>` and `a=fmtp`) and adopts the remote offer's negotiated dynamic payload type number per RFC 3264.
2. **Per-Call State Isolation (`CodecRegistry`):** Calls `factory.create()` when each call establishes so encoder/decoder predictor states never leak across concurrent calls.
3. **Sample Rate Adaptation (`AudioCodecPlugin::encode_20ms` / `decode_20ms`):** Automatically converts between your `AudioPort` rate (`8`/`16`/`48` kHz) and your codec's `pcm_sample_rate_hz`.
4. **RTP Clock & Jitter Scaling (`MediaSession::new_with_plugin`):** Advances RTP timestamps by `rtp_clock_rate_hz / 50` and scales RFC 3550 jitter estimates into PCM frame units for `AdaptiveJitterBuffer`.

---

## 5. SRTP & SRTCP Media Encryption (`RFC 3711`, `SDES`)

[`crates/bmsip-media/src/srtp.rs`](../crates/bmsip-media/src/srtp.rs) implements RFC 3711 SRTP & SRTCP completely in Pure Safe Rust (`#![forbid(unsafe_code)]`, zero external crate dependencies):

- **Cryptographic Suites (`SrtpSuite`):**
  - `AES_CM_128_HMAC_SHA1_80` (16-byte master key, 14-byte master salt, 80-bit / 10-byte RTP & SRTCP HMAC-SHA1 tags)
  - `AES_CM_128_HMAC_SHA1_32` (16-byte master key, 14-byte master salt, 32-bit / 4-byte RTP tag, 80-bit / 10-byte SRTCP tag)
- **RFC 3711 §4.3.1 KDF, Per-SSRC Replay Protection & Key Hygiene:** Derives separate session cipher, auth, and salt keys for RTP and RTCP (verified against RFC 3711 Appendix B.3 test vectors), tracks 32-bit `ROC` and 64-packet sliding replay windows independently per authenticated SSRC (handling mid-call PBX SSRC switches without ROC desync), enforces RFC 3711 §9.2 packet limits (`MediaError::SrtpKeyExpired`), compares MAC tags in constant time, and wipes key buffers on `Drop`.
- **Key Exchange Modes (`SrtpMode`):**
  - `SrtpMode::SdesRequired` (RFC 4568): Negotiates `RTP/SAVP` with `a=crypto:<tag> <suite> inline:<base64>` derived via HMAC-SHA256 from a 256-bit OS CSPRNG secret (`UaConfig::crypto_seed`), requires `SipTransport::Tls` by default (RFC 4568 §8), rejects unsupported MKI lines, preserves keys across Hold `re-INVITE`, and selectively rotates keys on `re-INVITE` / `183 -> 200 OK` forking (`MediaSession::update_srtp_keys`).
  - `SrtpMode::SdesOptional`: Offers opportunistic `a=crypto:` over `SipTransport::Tls` (automatically suppressed over unencrypted UDP/TCP unless `allow_insecure_cleartext_sdes` is explicitly enabled) and interoperates with either `RTP/AVP` or `RTP/SAVP`.
  - Incoming `UDP/TLS/RTP/SAVP(F)` (DTLS-SRTP) offers are rejected with `488 Not Acceptable Here`; internal DTLS scaffolding is isolated behind the off-by-default `experimental-dtls` Cargo feature.

---

## 6. RTCP Compound Reports, DTMF Pacing & Comfort Noise (`RFC 3550`, `RFC 4733`, `RFC 3389`)

- **Compound `RR + SDES(CNAME)` & `DLSR`:** [`MediaSession`](../crates/bmsip-media/src/session.rs) emits compound RTCP `ReceiverReport` + `Sdes` (`SDES_CNAME`, configurable via `MediaSession::with_cname`) packets. `RtpStreamStats` computes modular 32-bit interarrival jitter (immune to 32-bit RTP timestamp wraparound) and `DLSR` via `receive_rtcp_at` / `build_rtcp_receiver_report_at`.
- **RFC 3550 Appendix A.1 Probation & `a=rtcp:` / `a=rtcp-mux` Demuxing:** `RtpStreamStats` enforces `MAX_DROPOUT = 3000` / `MAX_MISORDER = 100` (`SeqStatus::ProbationRejected` / `SeqStatus::Resynced`) so single corrupted sequence jumps neither stall stream playout nor reset the jitter buffer; `MediaSession::receive_rtp` additionally requires 2 sequential packets (`probation_ssrc`) before switching SSRC on unencrypted streams (authenticated SRTP switches immediately after HMAC-SHA1 verification). `SipEngine` honors RFC 3605 `a=rtcp:` explicit destination ports and RFC 5761 `a=rtcp-mux` multiplexed RTP/RTCP sockets.
- **DTMF & DTX Isolation:** Inbound RFC 4733 DTMF and RFC 3389 CN (`PT 13`) packets update sequence/loss counters via `RtpStreamStats::record_non_audio_packet` without polluting jitter estimates or jitter buffer depth. Outbound `DtmfSender` enforces monotonically advancing timestamps when multiple digits are queued in the same tick, and both CN SID transmission and outbound DTMF set the RTP marker bit (`M=1`) on the next speech frame.
