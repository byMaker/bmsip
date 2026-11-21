//! MODULE_CONTRACT: Unified Sans-I/O 20 ms PCM <-> RTP/RTCP/DTMF media session pipeline (`MediaSession`).
//! INVARIANTS: Zero OS audio or socket APIs; operates strictly on byte slices and 20 ms `i16` PCM frames; routes DTMF payload type to `DtmfDetector`, G.711, G.722, Opus, and custom plugin payload types to `AdaptiveJitterBuffer`.
//! RFC_REFS: RFC 3389, RFC 3550, RFC 3551, RFC 4733, RFC 7587.

use bmsip_core::sdp::SrtpSuite;

use crate::cn::{ComfortNoiseGenerator, ComfortNoisePacket, CN_PAYLOAD_TYPE};
use crate::codec::G711Kind;
use crate::dtmf::{DtmfDetector, DtmfDigit, DtmfEventPayload, DtmfSender};
use crate::error::MediaError;
use crate::g722::{
    G722Codec, StreamResampler, G722_PAYLOAD_TYPE, G722_RTP_CLOCK_RATE, G722_RTP_SAMPLES_20MS,
    PCM_FRAME_SAMPLES_16KHZ_20MS,
};
use crate::jitter::{AdaptiveJitterBuffer, JitterBufferConfig, PlayoutFrame};
use crate::opus::{
    BuiltInOpusCodec, OpusCodecBackend, OPUS_RTP_CLOCK_RATE, OPUS_RTP_SAMPLES_20MS,
    PCM_FRAME_SAMPLES_48KHZ_20MS, PCM_FRAME_SAMPLES_8KHZ_20MS,
};
use crate::plugin::AudioCodecPlugin;
use crate::rtcp::{RtcpPacket, RtpStreamStats};
use crate::rtp::{RtpPacketRef, RtpPacketizer};
use crate::srtp::SrtpContext;

/// Active audio codec selected for [`MediaSession`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionCodec {
    G711(G711Kind),
    G722 {
        payload_type: u8,
    },
    Opus {
        payload_type: u8,
    },
    Custom {
        payload_type: u8,
        rtp_clock_rate_hz: u32,
    },
}

impl SessionCodec {
    /// Standard static ITU-T G.722 codec entry (payload type `9`, `8000` Hz RTP clock per RFC 3551).
    pub fn g722() -> Self {
        Self::G722 {
            payload_type: G722_PAYLOAD_TYPE,
        }
    }

    /// Returns the RTP payload type number used for outbound media packets.
    pub fn payload_type(self) -> u8 {
        match self {
            Self::G711(k) => k.payload_type(),
            Self::G722 { payload_type }
            | Self::Opus { payload_type }
            | Self::Custom { payload_type, .. } => payload_type,
        }
    }

    /// Returns the RTP clock rate in Hz (`8000` for G.711/G.722, `48000` for Opus, or custom rate).
    pub fn clock_rate_hz(self) -> u32 {
        match self {
            Self::G711(_) => 8_000,
            Self::G722 { .. } => G722_RTP_CLOCK_RATE,
            Self::Opus { .. } => OPUS_RTP_CLOCK_RATE,
            Self::Custom {
                rtp_clock_rate_hz, ..
            } => rtp_clock_rate_hz,
        }
    }
}

/// Integrated Sans-I/O audio media pipeline combining packetizer, built-in or pluggable codecs, DTMF, jitter buffer, and RTCP stats.
#[derive(Debug)]
pub struct MediaSession {
    codec: SessionCodec,
    opus: Box<dyn OpusCodecBackend>,
    g722: G722Codec,
    custom_plugin: Option<Box<dyn AudioCodecPlugin>>,
    tx_resampler: StreamResampler,
    rx_resampler: StreamResampler,
    dtmf_payload_type: u8,
    dtmf_clock_rate_hz: u32,
    cn_payload_type: u8,
    frame_samples: usize,
    packetizer: RtpPacketizer,
    jitter: AdaptiveJitterBuffer,
    stats: RtpStreamStats,
    dtmf_sender: DtmfSender,
    dtmf_detector: DtmfDetector,
    cn_generator: ComfortNoiseGenerator,
    remote_ssrc: Option<u32>,
    srtp_tx: Option<SrtpContext>,
    srtp_rx: Option<SrtpContext>,
    srtp_tx_key_fingerprint: Option<(SrtpSuite, [u8; 30])>,
    srtp_rx_key_fingerprint: Option<(SrtpSuite, [u8; 30])>,
}

impl Drop for MediaSession {
    fn drop(&mut self) {
        if let Some((_, ref mut key)) = self.srtp_tx_key_fingerprint {
            for b in key.iter_mut() {
                *b = 0;
            }
            std::hint::black_box(key);
        }
        if let Some((_, ref mut key)) = self.srtp_rx_key_fingerprint {
            for b in key.iter_mut() {
                *b = 0;
            }
            std::hint::black_box(key);
        }
    }
}

impl MediaSession {
    /// Creates a [`MediaSession`] configured for a G.711 codec and `dtmf_payload_type`.
    pub fn new(
        codec: G711Kind,
        dtmf_payload_type: u8,
        local_ssrc: u32,
        jitter_config: JitterBufferConfig,
    ) -> Self {
        Self::new_with_session_codec(
            SessionCodec::G711(codec),
            dtmf_payload_type,
            local_ssrc,
            jitter_config,
        )
    }

    /// Creates a [`MediaSession`] configured for any [`SessionCodec`] (`G711`, `G722`, `Opus`, or `Custom`).
    pub fn new_with_session_codec(
        codec: SessionCodec,
        dtmf_payload_type: u8,
        local_ssrc: u32,
        jitter_config: JitterBufferConfig,
    ) -> Self {
        let frame_samples = jitter_config.frame_samples.max(1);
        let dtmf_clock_rate_hz = codec.clock_rate_hz().max(8_000);
        Self {
            codec,
            opus: Box::new(BuiltInOpusCodec::new()),
            g722: G722Codec::new(),
            custom_plugin: None,
            tx_resampler: StreamResampler::new(),
            rx_resampler: StreamResampler::new(),
            dtmf_payload_type,
            dtmf_clock_rate_hz,
            cn_payload_type: CN_PAYLOAD_TYPE,
            frame_samples,
            packetizer: RtpPacketizer::new(local_ssrc, codec.payload_type(), 1, 0),
            jitter: AdaptiveJitterBuffer::new(jitter_config),
            stats: RtpStreamStats::new(),
            dtmf_sender: DtmfSender::new(),
            dtmf_detector: DtmfDetector::new(),
            cn_generator: ComfortNoiseGenerator::new(),
            remote_ssrc: None,
            srtp_tx: None,
            srtp_rx: None,
            srtp_tx_key_fingerprint: None,
            srtp_rx_key_fingerprint: None,
        }
    }

    /// Creates a [`MediaSession`] driven by an arbitrary pluggable [`AudioCodecPlugin`].
    pub fn new_with_plugin(
        plugin: Box<dyn AudioCodecPlugin>,
        payload_type: u8,
        dtmf_payload_type: u8,
        local_ssrc: u32,
        jitter_config: JitterBufferConfig,
    ) -> Self {
        let codec = SessionCodec::Custom {
            payload_type,
            rtp_clock_rate_hz: plugin.descriptor().rtp_clock_rate_hz,
        };
        Self::new_with_session_codec(codec, dtmf_payload_type, local_ssrc, jitter_config)
            .with_codec_plugin(plugin)
    }

    /// Installs a custom [`OpusCodecBackend`] (such as native `LibOpusCodec`) using builder style.
    pub fn with_opus_backend(mut self, backend: Box<dyn OpusCodecBackend>) -> Self {
        self.opus = backend;
        self
    }

    /// Installs a custom [`AudioCodecPlugin`] backend using builder style.
    pub fn with_codec_plugin(mut self, plugin: Box<dyn AudioCodecPlugin>) -> Self {
        self.custom_plugin = Some(plugin);
        self
    }

    /// Sets the RTP clock rate in Hz for RFC 4733 `telephone-event` DTMF duration scaling.
    pub fn with_dtmf_clock_rate(mut self, clock_rate_hz: u32) -> Self {
        self.dtmf_clock_rate_hz = clock_rate_hz.max(8_000);
        self
    }

    /// Sets the negotiated RFC 3389 Comfort Noise payload type (defaults to `13`).
    pub fn with_cn_payload_type(mut self, payload_type: u8) -> Self {
        self.cn_payload_type = payload_type;
        self
    }

    /// Configures outbound TX and inbound RX RFC 3711 SRTP/SRTCP keys using builder style.
    pub fn with_srtp_keys(
        mut self,
        suite: SrtpSuite,
        tx_key_salt: &[u8; 30],
        rx_key_salt: &[u8; 30],
    ) -> Self {
        self.set_srtp_keys(suite, tx_key_salt, rx_key_salt);
        self
    }

    /// Installs or replaces outbound TX and inbound RX RFC 3711 SRTP/SRTCP contexts unconditionally.
    pub fn set_srtp_keys(
        &mut self,
        suite: SrtpSuite,
        tx_key_salt: &[u8; 30],
        rx_key_salt: &[u8; 30],
    ) {
        self.srtp_tx = Some(SrtpContext::from_key_salt(suite, tx_key_salt));
        self.srtp_rx = Some(SrtpContext::from_key_salt(suite, rx_key_salt));
        self.srtp_tx_key_fingerprint = Some((suite, *tx_key_salt));
        self.srtp_rx_key_fingerprint = Some((suite, *rx_key_salt));
    }

    /// Installs or selectively rotates TX and/or RX SRTP contexts only for directions whose suite or key changed.
    ///
    /// Preserves existing ROC and replay windows across mid-call `re-INVITE` exchanges when keys remain unchanged
    /// (RFC 4568 §6.1.3), while immediately rotating RX keys on `183 -> 200 OK` forking or PBX re-keying.
    /// Returns `true` if either direction was newly initialized or rotated.
    pub fn update_srtp_keys(
        &mut self,
        suite: SrtpSuite,
        tx_key_salt: &[u8; 30],
        rx_key_salt: &[u8; 30],
    ) -> bool {
        let mut changed = false;
        let next_tx = (suite, *tx_key_salt);
        if self.srtp_tx.is_none() || self.srtp_tx_key_fingerprint.as_ref() != Some(&next_tx) {
            self.srtp_tx = Some(SrtpContext::from_key_salt(suite, tx_key_salt));
            self.srtp_tx_key_fingerprint = Some(next_tx);
            changed = true;
        }
        let next_rx = (suite, *rx_key_salt);
        if self.srtp_rx.is_none() || self.srtp_rx_key_fingerprint.as_ref() != Some(&next_rx) {
            self.srtp_rx = Some(SrtpContext::from_key_salt(suite, rx_key_salt));
            self.srtp_rx_key_fingerprint = Some(next_rx);
            changed = true;
        }
        changed
    }

    /// Clears any installed SRTP/SRTCP keys, reverting to plain RTP/RTCP.
    pub fn clear_srtp(&mut self) {
        self.srtp_tx = None;
        self.srtp_rx = None;
        self.srtp_tx_key_fingerprint = None;
        self.srtp_rx_key_fingerprint = None;
    }

    /// Returns `true` when SRTP media encryption is active on this session.
    pub fn is_srtp_active(&self) -> bool {
        self.srtp_tx.is_some() && self.srtp_rx.is_some()
    }

    /// Returns the active [`SrtpSuite`] if SRTP is enabled on this session.
    pub fn srtp_suite(&self) -> Option<SrtpSuite> {
        self.srtp_tx.as_ref().map(SrtpContext::suite)
    }

    /// Replaces the active [`OpusCodecBackend`].
    pub fn set_opus_backend(&mut self, backend: Box<dyn OpusCodecBackend>) {
        self.opus = backend;
    }

    /// Returns the currently active [`SessionCodec`].
    pub fn codec(&self) -> SessionCodec {
        self.codec
    }

    /// Returns the configured RFC 4733 DTMF payload type.
    pub fn dtmf_payload_type(&self) -> u8 {
        self.dtmf_payload_type
    }

    /// Returns the configured RFC 4733 DTMF RTP clock rate in Hz.
    pub fn dtmf_clock_rate_hz(&self) -> u32 {
        self.dtmf_clock_rate_hz
    }

    /// Returns the configured RFC 3389 Comfort Noise (`CN`) payload type.
    pub fn cn_payload_type(&self) -> u8 {
        self.cn_payload_type
    }

    /// Returns `true` when inbound RFC 3389 Comfort Noise synthesis is active for DTX pauses.
    pub fn is_comfort_noise_active(&self) -> bool {
        self.cn_generator.is_active()
    }

    /// Returns the last observed remote RTP SSRC, if any packet has been received.
    pub fn remote_ssrc(&self) -> Option<u32> {
        self.remote_ssrc
    }

    /// Reconfigures the active media codec and DTMF parameters mid-call (e.g., after `re-INVITE`).
    pub fn reconfigure_codec(
        &mut self,
        codec: SessionCodec,
        dtmf_payload_type: u8,
        dtmf_clock_rate_hz: u32,
        custom_plugin: Option<Box<dyn AudioCodecPlugin>>,
    ) {
        if self.codec != codec {
            self.tx_resampler.reset();
            self.rx_resampler.reset();
        }
        self.codec = codec;
        self.dtmf_payload_type = dtmf_payload_type;
        self.dtmf_clock_rate_hz = dtmf_clock_rate_hz.max(8_000);
        self.custom_plugin = custom_plugin;
        self.packetizer.set_payload_type(codec.payload_type());
    }

    /// Returns the RTP clock rate in Hz for the active [`SessionCodec`].
    pub fn clock_rate_hz(&self) -> u32 {
        self.codec.clock_rate_hz()
    }

    /// Encodes one 20 ms mono PCM frame into an outbound RTP datagram.
    pub fn encode_pcm_frame(&mut self, pcm: &[i16]) -> Result<Vec<u8>, MediaError> {
        if pcm.len() != self.frame_samples {
            return Err(MediaError::BufferError(format!(
                "expected {} PCM samples, got {}",
                self.frame_samples,
                pcm.len()
            )));
        }
        let (encoded, ts_advance) = if let Some(plugin) = self.custom_plugin.as_mut() {
            (plugin.encode_20ms(pcm)?, self.codec.clock_rate_hz() / 50)
        } else {
            match self.codec {
                SessionCodec::G711(kind) => {
                    if self.frame_samples != PCM_FRAME_SAMPLES_8KHZ_20MS {
                        let pcm_8k = self
                            .tx_resampler
                            .resample_20ms(pcm, PCM_FRAME_SAMPLES_8KHZ_20MS)?;
                        (kind.encode(&pcm_8k), PCM_FRAME_SAMPLES_8KHZ_20MS as u32)
                    } else {
                        (kind.encode(pcm), PCM_FRAME_SAMPLES_8KHZ_20MS as u32)
                    }
                }
                SessionCodec::G722 { .. } => {
                    let pkt = if self.frame_samples == PCM_FRAME_SAMPLES_16KHZ_20MS {
                        self.g722.encode_16khz(pcm)?
                    } else {
                        let pcm_16k = self
                            .tx_resampler
                            .resample_20ms(pcm, PCM_FRAME_SAMPLES_16KHZ_20MS)?;
                        self.g722.encode_16khz(&pcm_16k)?
                    };
                    (pkt, G722_RTP_SAMPLES_20MS)
                }
                SessionCodec::Opus { .. } => {
                    let pkt = if self.frame_samples == PCM_FRAME_SAMPLES_48KHZ_20MS {
                        self.opus.encode_20ms_48khz(pcm)?
                    } else if self.frame_samples == PCM_FRAME_SAMPLES_8KHZ_20MS {
                        self.opus.encode_20ms_8khz(pcm)?
                    } else {
                        let pcm_48k = self
                            .tx_resampler
                            .resample_20ms(pcm, PCM_FRAME_SAMPLES_48KHZ_20MS)?;
                        self.opus.encode_20ms_48khz(&pcm_48k)?
                    };
                    (pkt, OPUS_RTP_SAMPLES_20MS)
                }
                SessionCodec::Custom { payload_type, .. } => {
                    return Err(MediaError::UnsupportedCodec(format!(
                        "custom session codec PT {payload_type} requires an installed AudioCodecPlugin"
                    )));
                }
            }
        };
        let rtp_pkt = self
            .packetizer
            .next_packet_bytes(&encoded, ts_advance, false);
        if let Some(srtp) = self.srtp_tx.as_mut() {
            srtp.protect_rtp(&rtp_pkt)
        } else {
            Ok(rtp_pkt)
        }
    }

    /// Queues an outbound RFC 4733 DTMF tone at the current media timestamp scaled by `dtmf_clock_rate_hz`.
    pub fn queue_dtmf(&mut self, digit: DtmfDigit) {
        let ts = self.packetizer.current_timestamp();
        self.dtmf_sender
            .queue_digit_with_clock_rate(digit, ts, self.dtmf_clock_rate_hz);
    }

    /// Pops the next queued RFC 4733 DTMF RTP (or SRTP) datagram for paced 20 ms transmission.
    pub fn pop_dtmf_packet(&mut self) -> Option<Vec<u8>> {
        self.dtmf_sender.pop_packet().and_then(|spec| {
            let payload = spec.payload.to_bytes();
            let raw = self.packetizer.build_custom_packet_bytes(
                self.dtmf_payload_type,
                spec.timestamp,
                spec.marker,
                &payload,
            );
            match self.srtp_tx.as_mut() {
                Some(srtp) => srtp.protect_rtp(&raw).ok(),
                None => Some(raw),
            }
        })
    }

    /// Drains queued outbound RFC 4733 DTMF RTP datagrams.
    pub fn poll_dtmf_packets(&mut self) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        while let Some(pkt) = self.pop_dtmf_packet() {
            out.push(pkt);
        }
        out
    }

    /// Encodes a 20 ms silence/noise PCM frame as an RFC 3389 Comfort Noise (`CN`) RTP SID packet.
    pub fn encode_comfort_noise_frame(&mut self, pcm: &[i16]) -> Result<Vec<u8>, MediaError> {
        if pcm.len() != self.frame_samples {
            return Err(MediaError::BufferError(format!(
                "expected {} PCM samples for CN SID, got {}",
                self.frame_samples,
                pcm.len()
            )));
        }
        let sid = ComfortNoisePacket::from_pcm_frame(pcm);
        Ok(self.build_comfort_noise_packet(sid.noise_level_dbov, &sid.spectral_params))
    }

    /// Builds an outbound RFC 3389 Comfort Noise (`CN`) RTP (or SRTP) SID packet with explicit `-dBov` and spectral parameters.
    pub fn build_comfort_noise_packet(
        &mut self,
        noise_level_dbov: u8,
        spectral_params: &[u8],
    ) -> Vec<u8> {
        let sid = ComfortNoisePacket::new(noise_level_dbov)
            .with_spectral_params(spectral_params.to_vec());
        let ts = self.packetizer.current_timestamp();
        let raw = self.packetizer.build_custom_packet_bytes(
            self.cn_payload_type,
            ts,
            false,
            &sid.to_bytes(),
        );
        match self.srtp_tx.as_mut() {
            Some(srtp) => srtp.protect_rtp(&raw).unwrap_or(raw),
            None => raw,
        }
    }

    /// Processes an inbound RTP (or SRTP) packet without intermediate payload allocations, updating RTCP stats and pushing decoded PCM or detecting DTMF.
    pub fn receive_rtp(
        &mut self,
        raw: &[u8],
        arrival_timestamp_samples: u32,
    ) -> Result<Option<DtmfDigit>, MediaError> {
        let decrypted_buf;
        let rtp_bytes = if let Some(srtp) = self.srtp_rx.as_mut() {
            decrypted_buf = srtp.unprotect_rtp(raw)?;
            decrypted_buf.as_slice()
        } else {
            raw
        };
        let pkt = RtpPacketRef::parse(rtp_bytes)?;
        // RFC 3550: a mid-call SSRC change (e.g., PBX bridge/transfer) starts a fresh sequence/timestamp domain.
        if let Some(prev_ssrc) = self.remote_ssrc {
            if prev_ssrc != pkt.ssrc {
                self.stats.reset();
                self.jitter.reset();
                self.dtmf_detector.reset();
                self.cn_generator.deactivate();
            }
        }
        self.remote_ssrc = Some(pkt.ssrc);
        self.stats.record_packet(
            pkt.sequence_number,
            pkt.timestamp,
            arrival_timestamp_samples,
        );

        if pkt.payload_type == self.dtmf_payload_type {
            let ev = DtmfEventPayload::parse(pkt.payload)?;
            self.jitter.mark_non_audio_seq(pkt.sequence_number);
            return Ok(self.dtmf_detector.feed(pkt.timestamp, ev));
        }

        if pkt.payload_type == self.cn_payload_type || pkt.payload_type == CN_PAYLOAD_TYPE {
            let cn_pkt = ComfortNoisePacket::parse(pkt.payload)?;
            self.cn_generator.update_from_packet(&cn_pkt);
            let cn_pcm = self.cn_generator.generate_frame(self.frame_samples);
            self.jitter
                .push(pkt.sequence_number, cn_pcm, self.stats.jitter());
            return Ok(None);
        }

        self.cn_generator.deactivate();

        let pcm = if let Some(plugin) = self.custom_plugin.as_mut() {
            if pkt.payload_type == self.codec.payload_type() {
                plugin.decode_20ms(pkt.payload, self.frame_samples)?
            } else {
                decode_fallback_builtin(
                    &mut self.g722,
                    &mut self.rx_resampler,
                    pkt.payload_type,
                    pkt.payload,
                    self.frame_samples,
                )?
            }
        } else if matches!(self.codec, SessionCodec::Opus { payload_type } if payload_type == pkt.payload_type)
        {
            if self.frame_samples == PCM_FRAME_SAMPLES_48KHZ_20MS {
                self.opus.decode_20ms_48khz(pkt.payload)?
            } else if self.frame_samples == PCM_FRAME_SAMPLES_16KHZ_20MS {
                let pcm_48k = self.opus.decode_20ms_48khz(pkt.payload)?;
                self.rx_resampler
                    .resample_20ms(&pcm_48k, PCM_FRAME_SAMPLES_16KHZ_20MS)?
            } else {
                self.opus.decode_20ms_8khz(pkt.payload)?
            }
        } else if matches!(self.codec, SessionCodec::G722 { payload_type } if payload_type == pkt.payload_type)
            || pkt.payload_type == G722_PAYLOAD_TYPE
        {
            let pcm_16k = self.g722.decode_16khz(pkt.payload)?;
            if self.frame_samples == PCM_FRAME_SAMPLES_16KHZ_20MS {
                pcm_16k
            } else {
                self.rx_resampler
                    .resample_20ms(&pcm_16k, self.frame_samples)?
            }
        } else {
            decode_fallback_builtin(
                &mut self.g722,
                &mut self.rx_resampler,
                pkt.payload_type,
                pkt.payload,
                self.frame_samples,
            )?
        };

        let rtp_samples_per_frame = self.codec.clock_rate_hz() / 50;
        let scaled_jitter =
            if rtp_samples_per_frame > 0 && rtp_samples_per_frame != self.frame_samples as u32 {
                ((u64::from(self.stats.jitter()) * u64::from(self.frame_samples as u32))
                    / u64::from(rtp_samples_per_frame)) as u32
            } else {
                self.stats.jitter()
            };

        self.jitter.push(pkt.sequence_number, pcm, scaled_jitter);
        Ok(None)
    }

    /// Processes an inbound compound RTCP (or SRTCP) datagram, recording any Sender Report NTP timestamps (`LSR`).
    pub fn receive_rtcp(&mut self, raw: &[u8]) -> Result<usize, MediaError> {
        let decrypted_buf;
        let rtcp_bytes = if let Some(srtp) = self.srtp_rx.as_mut() {
            decrypted_buf = srtp.unprotect_rtcp(raw)?;
            decrypted_buf.as_slice()
        } else {
            raw
        };
        let packets = RtcpPacket::parse_compound(rtcp_bytes)?;
        let count = packets.len();
        for pkt in packets {
            if let RtcpPacket::SenderReport { sender_info, .. } = pkt {
                self.stats.record_sender_report(sender_info.ntp_timestamp);
            }
        }
        Ok(count)
    }

    /// Pops the next 20 ms playout frame from the adaptive jitter buffer (synthesizing RFC 3389 comfort noise when DTX SID is active).
    pub fn pop_playout_frame(&mut self) -> PlayoutFrame {
        let frame = self.jitter.pop();
        if self.cn_generator.is_active()
            && matches!(
                frame,
                PlayoutFrame::Buffering(_) | PlayoutFrame::Concealed(_)
            )
        {
            return PlayoutFrame::ComfortNoise(
                self.cn_generator.generate_frame(self.frame_samples),
            );
        }
        frame
    }

    /// Builds an RTCP (or SRTCP when SRTP is active) Receiver Report (`RR`) packet and advances RFC 3550 §6.4.1 interval loss counters.
    pub fn build_rtcp_receiver_report(&mut self) -> Vec<u8> {
        let reports = match self.remote_ssrc {
            Some(rssrc) => vec![self.stats.build_reception_report(rssrc)],
            None => Vec::new(),
        };
        let raw = RtcpPacket::ReceiverReport {
            ssrc: self.packetizer.ssrc(),
            reports,
        }
        .to_bytes();
        match self.srtp_tx.as_mut() {
            Some(srtp) => srtp.protect_rtcp(&raw).unwrap_or(raw),
            None => raw,
        }
    }

    /// Builds a non-mutating snapshot RTCP Receiver Report (`RR`) packet without advancing interval counters.
    pub fn snapshot_rtcp_receiver_report(&self) -> Vec<u8> {
        let reports = match self.remote_ssrc {
            Some(rssrc) => vec![self.stats.snapshot_reception_report(rssrc)],
            None => Vec::new(),
        };
        RtcpPacket::ReceiverReport {
            ssrc: self.packetizer.ssrc(),
            reports,
        }
        .to_bytes()
    }

    /// Returns receiver RTP statistics.
    pub fn stats(&self) -> &RtpStreamStats {
        &self.stats
    }

    /// Returns the jitter buffer's current adaptive target depth in frames.
    pub fn jitter_target_depth(&self) -> usize {
        self.jitter.target_depth_frames()
    }
}

fn decode_fallback_builtin(
    g722: &mut G722Codec,
    resampler: &mut StreamResampler,
    payload_type: u8,
    payload: &[u8],
    target_frame_samples: usize,
) -> Result<Vec<i16>, MediaError> {
    if payload_type == G722_PAYLOAD_TYPE {
        let pcm_16k = g722.decode_16khz(payload)?;
        return if target_frame_samples == PCM_FRAME_SAMPLES_16KHZ_20MS {
            Ok(pcm_16k)
        } else {
            resampler.resample_20ms(&pcm_16k, target_frame_samples)
        };
    }

    let rx_codec = G711Kind::from_payload_type(payload_type).ok_or_else(|| {
        MediaError::UnsupportedCodec(format!("unsupported RTP payload type {payload_type}"))
    })?;
    let pcm_8k = rx_codec.decode(payload);
    if target_frame_samples == PCM_FRAME_SAMPLES_8KHZ_20MS {
        Ok(pcm_8k)
    } else {
        resampler.resample_20ms(&pcm_8k, target_frame_samples)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtp::RtpPacket;
    use crate::wav::WavPcm16;

    #[test]
    fn media_session_end_to_end_audio_dtmf_and_rtcp() {
        let cfg = JitterBufferConfig {
            min_depth_frames: 2,
            max_depth_frames: 8,
            initial_depth_frames: 2,
            frame_samples: 160,
        };
        let mut tx = MediaSession::new(G711Kind::Pcmu, 101, 0xaaaa_0001, cfg);
        let mut rx = MediaSession::new(G711Kind::Pcmu, 101, 0xbbbb_0002, cfg);

        let tone = WavPcm16::generate_sine_wave(8000, 400, 200, 12000);
        let mut arrival_ts = 0u32;
        for frame in tone.samples.as_chunks::<160>().0 {
            let rtp = tx.encode_pcm_frame(frame).unwrap();
            assert_eq!(rx.receive_rtp(&rtp, arrival_ts).unwrap(), None);
            arrival_ts += 160;
        }

        tx.queue_dtmf(DtmfDigit::D9);
        let mut digits = Vec::new();
        for dtmf_pkt in tx.poll_dtmf_packets() {
            if let Some(d) = rx.receive_rtp(&dtmf_pkt, arrival_ts).unwrap() {
                digits.push(d);
            }
        }
        assert_eq!(digits, vec![DtmfDigit::D9]);

        let mut played_samples = Vec::new();
        for _ in 0..10 {
            let pf = rx.pop_playout_frame();
            assert!(matches!(pf, PlayoutFrame::Normal(_)));
            played_samples.extend_from_slice(pf.samples());
        }
        let played_wav = WavPcm16::new(8000, played_samples);
        assert!(played_wav.rms_energy() > 6000);

        let rr_bytes = rx.build_rtcp_receiver_report();
        let parsed_rr = RtcpPacket::parse_compound(&rr_bytes).unwrap();
        assert!(matches!(
            parsed_rr.as_slice(),
            [RtcpPacket::ReceiverReport {
                ssrc: 0xbbbb_0002,
                ..
            }]
        ));
    }

    #[test]
    fn opus_media_session_uses_48khz_timestamps_and_roundtrips() {
        let cfg = JitterBufferConfig {
            min_depth_frames: 2,
            max_depth_frames: 8,
            initial_depth_frames: 2,
            frame_samples: 160,
        };
        let mut tx = MediaSession::new_with_session_codec(
            SessionCodec::Opus { payload_type: 111 },
            101,
            0xcccc_0001,
            cfg,
        );
        let mut rx = MediaSession::new_with_session_codec(
            SessionCodec::Opus { payload_type: 111 },
            101,
            0xdddd_0002,
            cfg,
        );
        assert_eq!(tx.clock_rate_hz(), 48_000);

        let tone = WavPcm16::generate_sine_wave(8000, 400, 100, 12000);
        let mut ts_list = Vec::new();
        for (idx, frame) in tone.samples.as_chunks::<160>().0.iter().enumerate() {
            let rtp = tx.encode_pcm_frame(frame).unwrap();
            let parsed = RtpPacket::parse(&rtp).unwrap();
            assert_eq!(parsed.header.payload_type, 111);
            ts_list.push(parsed.header.timestamp);
            rx.receive_rtp(&rtp, (idx as u32) * 960).unwrap();
        }
        assert_eq!(ts_list, vec![0, 960, 1920, 2880, 3840]);

        let mut played = Vec::new();
        for _ in 0..5 {
            played.extend_from_slice(rx.pop_playout_frame().samples());
        }
        assert!(WavPcm16::new(8000, played).rms_energy() > 6000);
    }

    #[test]
    fn g722_media_session_uses_8khz_rtp_clock_for_16khz_wideband_audio() {
        let cfg = JitterBufferConfig {
            min_depth_frames: 2,
            max_depth_frames: 8,
            initial_depth_frames: 2,
            frame_samples: PCM_FRAME_SAMPLES_16KHZ_20MS,
        };
        let mut tx =
            MediaSession::new_with_session_codec(SessionCodec::g722(), 101, 0xeeee_0001, cfg);
        let mut rx =
            MediaSession::new_with_session_codec(SessionCodec::g722(), 101, 0xffff_0002, cfg);
        assert_eq!(tx.clock_rate_hz(), 8_000);

        let tone = WavPcm16::generate_sine_wave(16_000, 3_000, 200, 12_000);
        let mut ts_list = Vec::new();
        for (idx, frame) in tone.samples.as_chunks::<320>().0.iter().enumerate() {
            let rtp = tx.encode_pcm_frame(frame).unwrap();
            let parsed = RtpPacket::parse(&rtp).unwrap();
            assert_eq!(parsed.header.payload_type, 9);
            ts_list.push(parsed.header.timestamp);
            rx.receive_rtp(&rtp, (idx as u32) * 160).unwrap();
        }
        assert_eq!(ts_list[..5], [0, 160, 320, 480, 640]);

        let mut played = Vec::new();
        for _ in 0..10 {
            played.extend_from_slice(rx.pop_playout_frame().samples());
        }
        assert!(WavPcm16::new(16_000, played[640..].to_vec()).rms_energy() > 6000);
    }

    #[test]
    fn deterministic_mutation_fuzz_rtp_rtcp_dtmf_and_codecs_never_panic() {
        use crate::opus::{OpusFmtp, OpusToc};

        let mut prng: u64 = 0x9e37_79b9_7f4a_7c15;
        let next_u64 = |state: &mut u64| -> u64 {
            *state ^= *state << 13;
            *state ^= *state >> 7;
            *state ^= *state << 17;
            *state
        };

        let valid_rtp = [
            0x80, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xa0, 0x11, 0x22, 0x33, 0x44, 0xff, 0x7f,
        ];
        let valid_rtcp = RtcpPacket::ReceiverReport {
            ssrc: 0x1122_3344,
            reports: Vec::new(),
        }
        .to_bytes();

        let cfg = JitterBufferConfig::default();
        let mut session_pcmu = MediaSession::new(G711Kind::Pcmu, 101, 0x1010, cfg);
        let mut session_g722 = MediaSession::new_with_session_codec(
            SessionCodec::g722(),
            101,
            0x2020,
            JitterBufferConfig {
                frame_samples: PCM_FRAME_SAMPLES_16KHZ_20MS,
                ..cfg
            },
        );
        let mut g722 = G722Codec::new();
        let mut buf = Vec::with_capacity(256);

        for iter in 0..4_000usize {
            let len = (next_u64(&mut prng) as usize) % 240;
            buf.clear();
            let seed_src = match iter % 4 {
                0 => valid_rtp.as_slice(),
                1 => valid_rtcp.as_slice(),
                _ => &[],
            };
            for i in 0..len {
                let base = if i < seed_src.len() { seed_src[i] } else { 0 };
                let xor = if (next_u64(&mut prng) & 3) == 0 {
                    (next_u64(&mut prng) & 0xff) as u8
                } else {
                    0
                };
                buf.push(base ^ xor);
            }

            let _ = RtpPacketRef::parse(&buf);
            let _ = RtpPacket::parse(&buf);
            let _ = RtcpPacket::parse_compound(&buf);
            let _ = DtmfEventPayload::parse(&buf);
            if !buf.is_empty() {
                let _ = OpusToc::parse(buf[0]);
            }
            let txt = String::from_utf8_lossy(&buf);
            let _ = OpusFmtp::parse(&txt);
            let _ = g722.decode_16khz(&buf);
            let _ = session_pcmu.receive_rtp(&buf, iter as u32 * 160);
            let _ = session_pcmu.receive_rtcp(&buf);
            let _ = session_g722.receive_rtp(&buf, iter as u32 * 160);
        }
        let _ = session_pcmu.pop_playout_frame();
        let _ = session_g722.pop_playout_frame();
    }

    #[test]
    fn dtmf_48khz_opus_scales_duration_ticks_to_100ms() {
        let cfg = JitterBufferConfig {
            frame_samples: PCM_FRAME_SAMPLES_48KHZ_20MS,
            ..JitterBufferConfig::default()
        };
        let mut tx = MediaSession::new_with_session_codec(
            SessionCodec::Opus { payload_type: 111 },
            102,
            0x1234_5678,
            cfg,
        )
        .with_dtmf_clock_rate(48_000);
        tx.queue_dtmf(DtmfDigit::D5);
        let pkts = tx.poll_dtmf_packets();
        assert_eq!(pkts.len(), 7);
        let durations: Vec<u16> = pkts
            .iter()
            .map(|raw| {
                let parsed = RtpPacket::parse(raw).unwrap();
                assert_eq!(parsed.header.payload_type, 102);
                DtmfEventPayload::parse(&parsed.payload).unwrap().duration
            })
            .collect();
        assert_eq!(durations, vec![960, 1920, 2880, 3840, 4800, 4800, 4800]);
    }

    #[test]
    fn mid_call_remote_ssrc_change_resets_jitter_and_stats_seamlessly() {
        let cfg = JitterBufferConfig {
            min_depth_frames: 2,
            max_depth_frames: 8,
            initial_depth_frames: 2,
            frame_samples: 160,
        };
        let mut rx = MediaSession::new(G711Kind::Pcmu, 101, 0xbbbb_0002, cfg);

        // Stream 1 from SSRC A at high sequence numbers (500..505).
        let mut pkt_a = RtpPacketizer::new(0x1111_0001, 0, 500, 80_000);
        let tone_a = WavPcm16::generate_sine_wave(8000, 440, 100, 12000);
        for (i, frame) in tone_a.samples.as_chunks::<160>().0.iter().enumerate() {
            let wire = pkt_a.next_packet_bytes(&G711Kind::Pcmu.encode(frame), 160, false);
            rx.receive_rtp(&wire, i as u32 * 160).unwrap();
        }
        assert_eq!(rx.remote_ssrc(), Some(0x1111_0001));
        assert!(matches!(rx.pop_playout_frame(), PlayoutFrame::Normal(_)));

        // Mid-call bridge switches to SSRC B at low unrelated sequence numbers (10..15).
        let mut pkt_b = RtpPacketizer::new(0x2222_0002, 0, 10, 1_600);
        let tone_b = WavPcm16::generate_sine_wave(8000, 880, 120, 12000);
        for (i, frame) in tone_b.samples.as_chunks::<160>().0.iter().enumerate() {
            let wire = pkt_b.next_packet_bytes(&G711Kind::Pcmu.encode(frame), 160, false);
            rx.receive_rtp(&wire, 1000 + i as u32 * 160).unwrap();
        }
        assert_eq!(rx.remote_ssrc(), Some(0x2222_0002));
        assert_eq!(rx.stats().received_count(), 6);
        assert_eq!(rx.stats().cumulative_lost(), 0);
        assert!(rx.stats().jitter() < 50);

        let mut normal_count = 0usize;
        for _ in 0..6 {
            if matches!(rx.pop_playout_frame(), PlayoutFrame::Normal(_)) {
                normal_count += 1;
            }
        }
        assert_eq!(normal_count, 6);
    }

    #[test]
    fn rtcp_receiver_report_advances_interval_fraction_lost() {
        let cfg = JitterBufferConfig::default();
        let mut rx = MediaSession::new(G711Kind::Pcmu, 101, 0xaaaa_1111, cfg);
        let mut pkt = RtpPacketizer::new(0x9999_2222, 0, 1, 0);
        let payload = G711Kind::Pcmu.encode(&[0i16; 160]);

        // Interval 1: deliver seq 1, 3, 5, 7, 9, 10 (40% loss ending cleanly at seq 10).
        for i in 0..10u32 {
            let wire = pkt.next_packet_bytes(&payload, 160, false);
            if i % 2 == 0 || i == 9 {
                rx.receive_rtp(&wire, i * 160).unwrap();
            }
        }
        let rr1 = RtcpPacket::parse_compound(&rx.build_rtcp_receiver_report()).unwrap();
        let RtcpPacket::ReceiverReport { reports, .. } = &rr1[0] else {
            panic!("expected ReceiverReport");
        };
        assert!(
            reports[0].fraction_lost >= 100,
            "expected ~40% loss in interval 1, got {}",
            reports[0].fraction_lost
        );

        // Interval 2: deliver 10 clean consecutive packets -> fraction_lost must drop to 0.
        for i in 10..20u32 {
            let wire = pkt.next_packet_bytes(&payload, 160, false);
            rx.receive_rtp(&wire, i * 160).unwrap();
        }
        let rr2 = RtcpPacket::parse_compound(&rx.build_rtcp_receiver_report()).unwrap();
        let RtcpPacket::ReceiverReport { reports, .. } = &rr2[0] else {
            panic!("expected ReceiverReport");
        };
        assert_eq!(reports[0].fraction_lost, 0);
    }

    #[test]
    fn reconfigure_codec_updates_payload_type_and_dtmf_clock_rate() {
        let cfg = JitterBufferConfig {
            frame_samples: PCM_FRAME_SAMPLES_48KHZ_20MS,
            ..JitterBufferConfig::default()
        };
        let mut session = MediaSession::new(G711Kind::Pcmu, 101, 0x3333_4444, cfg);
        let frame = vec![0i16; PCM_FRAME_SAMPLES_48KHZ_20MS];
        let p0 = RtpPacket::parse(&session.encode_pcm_frame(&frame).unwrap()).unwrap();
        assert_eq!(p0.header.payload_type, 0);

        session.reconfigure_codec(SessionCodec::Opus { payload_type: 111 }, 102, 48_000, None);
        let p1 = RtpPacket::parse(&session.encode_pcm_frame(&frame).unwrap()).unwrap();
        assert_eq!(p1.header.payload_type, 111);
        assert_eq!(session.dtmf_payload_type(), 102);
        assert_eq!(session.dtmf_clock_rate_hz(), 48_000);
    }

    #[test]
    fn comfort_noise_rfc3389_sid_activates_dtx_synthesis_and_resumes_voice() {
        let cfg = JitterBufferConfig {
            min_depth_frames: 2,
            max_depth_frames: 8,
            initial_depth_frames: 2,
            frame_samples: 160,
        };
        let mut tx = MediaSession::new(G711Kind::Pcmu, 101, 0xaaaa_1001, cfg);
        let mut rx = MediaSession::new(G711Kind::Pcmu, 101, 0xbbbb_2002, cfg);
        assert_eq!(rx.cn_payload_type(), CN_PAYLOAD_TYPE);
        assert!(!rx.is_comfort_noise_active());

        // 1. Initial talkspurt of 3 voice frames primes the jitter buffer.
        let voice = WavPcm16::generate_sine_wave(8000, 440, 60, 8000);
        let mut ts = 0u32;
        for frame in voice.samples.as_chunks::<160>().0 {
            let pkt = tx.encode_pcm_frame(frame).unwrap();
            assert_eq!(rx.receive_rtp(&pkt, ts).unwrap(), None);
            ts += 160;
        }
        assert!(matches!(rx.pop_playout_frame(), PlayoutFrame::Normal(_)));
        assert!(matches!(rx.pop_playout_frame(), PlayoutFrame::Normal(_)));
        assert!(matches!(rx.pop_playout_frame(), PlayoutFrame::Normal(_)));

        // 2. Talkspurt ends -> sender transmits an RFC 3389 CN SID packet (-38 dBov).
        let cn_wire = tx.build_comfort_noise_packet(38, &[0x90]);
        let cn_parsed = RtpPacket::parse(&cn_wire).unwrap();
        assert_eq!(cn_parsed.header.payload_type, CN_PAYLOAD_TYPE);
        assert_eq!(rx.receive_rtp(&cn_wire, ts).unwrap(), None);
        assert!(rx.is_comfort_noise_active());

        // Drain queued SID frame, then pump DTX silence gap where no RTP arrives -> ComfortNoise frames.
        let _ = rx.pop_playout_frame();
        let cn1 = rx.pop_playout_frame();
        let cn2 = rx.pop_playout_frame();
        assert!(matches!(cn1, PlayoutFrame::ComfortNoise(_)));
        assert!(matches!(cn2, PlayoutFrame::ComfortNoise(_)));
        assert!(WavPcm16::new(8000, cn1.samples().to_vec()).rms_energy() > 50);

        // 3. New voice frame arrives -> deactivates CN and returns Normal playout.
        let next_voice = tx.encode_pcm_frame(&voice.samples[..160]).unwrap();
        rx.receive_rtp(&next_voice, ts + 480).unwrap();
        assert!(!rx.is_comfort_noise_active());
    }

    #[test]
    fn update_srtp_keys_rotates_only_changed_direction_and_preserves_unchanged_state() {
        let cfg = JitterBufferConfig::default();
        let tx_key = [0x11u8; 30];
        let rx_key_1 = [0x22u8; 30];
        let rx_key_2 = [0x33u8; 30];

        let mut alice = MediaSession::new(G711Kind::Pcmu, 101, 0x1000_0001, cfg);
        let mut bob_leg1 = MediaSession::new(G711Kind::Pcmu, 101, 0x2000_0001, cfg);
        let mut bob_leg2 = MediaSession::new(G711Kind::Pcmu, 101, 0x3000_0001, cfg);

        assert!(alice.update_srtp_keys(SrtpSuite::AesCm128HmacSha1_80, &tx_key, &rx_key_1));
        // Calling with identical keys (e.g., hold re-INVITE) must be a no-op returning false.
        assert!(!alice.update_srtp_keys(SrtpSuite::AesCm128HmacSha1_80, &tx_key, &rx_key_1));

        bob_leg1.set_srtp_keys(SrtpSuite::AesCm128HmacSha1_80, &rx_key_1, &tx_key);
        bob_leg2.set_srtp_keys(SrtpSuite::AesCm128HmacSha1_80, &rx_key_2, &tx_key);

        let frame = [0i16; 160];
        let p_a1 = alice.encode_pcm_frame(&frame).unwrap();
        assert!(bob_leg1.receive_rtp(&p_a1, 0).is_ok());

        let p_b1 = bob_leg1.encode_pcm_frame(&frame).unwrap();
        assert!(alice.receive_rtp(&p_b1, 0).is_ok());

        // Remote re-INVITE / 183->200 OK rotates RX key to rx_key_2 while TX key stays tx_key.
        assert!(alice.update_srtp_keys(SrtpSuite::AesCm128HmacSha1_80, &tx_key, &rx_key_2));
        let p_b2 = bob_leg2.encode_pcm_frame(&frame).unwrap();
        assert!(alice.receive_rtp(&p_b2, 160).is_ok());
        // Old RX key packets must now fail authentication.
        let p_b1_old = bob_leg1.encode_pcm_frame(&frame).unwrap();
        assert!(alice.receive_rtp(&p_b1_old, 320).is_err());
        // Outbound TX packets continue seamlessly under unchanged tx_key.
        let p_a2 = alice.encode_pcm_frame(&frame).unwrap();
        assert!(bob_leg1.receive_rtp(&p_a2, 160).is_ok());
    }
}
