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

- **`bmsip-engine::LibOpusCodec`** ([`crates/bmsip-engine/src/opus_native.rs`](../crates/bmsip-engine/src/opus_native.rs)): Links system `libopus` (`build.rs`) and implements `OpusCodecBackend` at `48000 Hz` mono using `OPUS_APPLICATION_VOIP`, `64 kbps` bitrate, complexity `8`, and optional in-band FEC (`OPUS_SET_INBAND_FEC(1)`).
- **`bmsip-media::BuiltInOpusCodec`** ([`crates/bmsip-media/src/opus.rs`](../crates/bmsip-media/src/opus.rs)): Pure-Rust `#![forbid(unsafe_code)]` fallback packing RFC 6716 TOC headers (`OpusToc`) and SDP `fmtp` parsing (`OpusFmtp`), used directly in pure-Rust sans-I/O unit tests.
- **`condition_mic_frame` (`bmsip-media::opus`)**: Pre-conditions raw microphone PCM frames using a **frame-level peak noise gate** (preventing zero-crossing crossover distortion), fixed-point `Q8` gain scaling, and rational soft-knee peak limiting within `[-32000, 32000]`.

### 1.2 Pure-Rust ITU-T G.722 (`bmsip-media::g722`)

[`crates/bmsip-media/src/g722.rs`](../crates/bmsip-media/src/g722.rs) implements Mode 1 (64 kbps) ITU-T G.722 completely in Safe Rust (`#![forbid(unsafe_code)]`) with zero external crates:

- **24-Tap QMF Analysis/Synthesis Bank:** Splits `16 kHz` audio into `0–4 kHz` lower and `4–8 kHz` upper subbands cleanly with unity gain.
- **SB-ADPCM Predictor (`G722Band::block4`):** 2-pole / 6-zero adaptive ARMA predictor + 6-bit lower / 2-bit upper quantizer tables matching ITU-T G.722 and `codec_g722.so` / `mod_spandsp`.
- **Anti-Aliasing FIR Resamplers & Cross-Frame `StreamResampler`:** Symmetric triangular low-pass FIR filters (`11`-tap for `48 -> 8 kHz`, `5`-tap for `48 -> 16 kHz`, `3`-tap `[1, 2, 1]/4` for `16 -> 8 kHz`) plus stateful boundary-continuous `StreamResampler` inside `MediaSession`.

---

## 2. RFC 4733 DTMF Telephone-Event Handling

- **Dual Clock Rates:** `RtpCodec::telephone_event(101)` (`8000 Hz`, paired with G.711/G.722) and `RtpCodec::telephone_event_48k(102)` (`48000 Hz`, paired with Opus for strict servers like FreeSWITCH `mod_sofia`).
- `SipEngine::on_call_established` automatically selects the negotiated `telephone-event` payload type matching the active codec's RTP clock rate.
- **Paced Transmission:** `DtmfSender` generates the 20 ms RFC 4733 event progression + 3 redundant end (`E=1`) packets, which `SipEngine::pump_media_tick` paces at 1 packet per 20 ms frame after the initial audio packets establish SSRC/clock baseline.
- **Deduplicating Reception:** `DtmfDetector` emits `EngineEvent::DtmfReceived { call_id, digit }` once per key press even when multiple end packets arrive.

---

## 3. Adaptive Jitter Buffer & Hardware-Agnostic `AudioPort`

### 3.1 `AudioPort` (`bmsip-engine::audio`)

`AudioPort` exchanges 20 ms mono `i16` frames every `MEDIA_TICK_MS = 20`:

- `sample_rate_hz(&self) -> u32`: declares `8000` (`160` samples), `16000` (`320` samples), or `48000` (`960` samples).
- `capture_frame_20ms(&mut self) -> Vec<i16>`: non-blocking mic/WAV frame supply.
- `playout_20ms(&mut self, samples: &[i16])`: non-blocking decoded speaker/WAV frame sink.

Built-in adapters: `NullAudioPort`, `WavAudioPort`/`WavAudioHandle` (supports `8`/`16`/`48` kHz WAV clips), `PcmQueueAudioPort`/`PcmAudioHandle`, and `LiveLinuxAudioPort` (`bmsip-cli`).

### 3.2 `AdaptiveJitterBuffer` (`bmsip-media::jitter`)

- **Out-of-Order Reordering:** Handles 16-bit RTP sequence rollover (RFC 3550 §5.1).
- **Dynamic Depth Adaptation:** Scales buffered target depth between `[min_depth_frames, max_depth_frames]` using RFC 3550 jitter estimates (`scaled_jitter` adjusted when `AudioPort` sample rate differs from RTP clock rate).
- **Decayed PLC & Boundary Crossfade:** Missing frames replay an attenuated copy (`7/8` exponential decay) of the last good frame; normal and concealed boundaries crossfade smoothly over up to 24 samples from `last_emitted_sample` to prevent audible phase clicks.

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
