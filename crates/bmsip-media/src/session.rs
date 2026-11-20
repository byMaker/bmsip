//! MODULE_CONTRACT: Unified Sans-I/O 20 ms PCM <-> RTP/RTCP/DTMF media session pipeline (`MediaSession`).
//! INVARIANTS: Zero OS audio or socket APIs; operates strictly on byte slices and 20 ms `i16` PCM frames; routes DTMF payload type to `DtmfDetector`, G.711 and Opus payload types to `AdaptiveJitterBuffer`.
//! RFC_REFS: RFC 3550, RFC 3551, RFC 4733, RFC 7587.

use crate::codec::G711Kind;
use crate::dtmf::{DtmfDetector, DtmfDigit, DtmfEventPayload, DtmfSender};
use crate::error::MediaError;
use crate::jitter::{AdaptiveJitterBuffer, JitterBufferConfig, PlayoutFrame};
use crate::opus::{
    downsample_48k_to_8k, upsample_8k_to_48k, BuiltInOpusCodec, OpusCodecBackend,
    OPUS_RTP_CLOCK_RATE, OPUS_RTP_SAMPLES_20MS, PCM_FRAME_SAMPLES_48KHZ_20MS,
    PCM_FRAME_SAMPLES_8KHZ_20MS,
};
use crate::rtcp::{RtcpPacket, RtpStreamStats};
use crate::rtp::{RtpPacket, RtpPacketizer};

/// Active audio codec selected for [`MediaSession`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionCodec {
    G711(G711Kind),
    Opus { payload_type: u8 },
}

impl SessionCodec {
    /// Returns the RTP payload type number used for outbound media packets.
    pub fn payload_type(self) -> u8 {
        match self {
            Self::G711(k) => k.payload_type(),
            Self::Opus { payload_type } => payload_type,
        }
    }

    /// Returns the RTP clock rate in Hz (`8000` for G.711, `48000` for Opus).
    pub fn clock_rate_hz(self) -> u32 {
        match self {
            Self::G711(_) => 8_000,
            Self::Opus { .. } => OPUS_RTP_CLOCK_RATE,
        }
    }
}

/// Integrated Sans-I/O audio media pipeline combining packetizer, G.711/Opus codec, DTMF, jitter buffer, and RTCP stats.
#[derive(Debug)]
pub struct MediaSession {
    codec: SessionCodec,
    opus: Box<dyn OpusCodecBackend>,
    dtmf_payload_type: u8,
    frame_samples: usize,
    packetizer: RtpPacketizer,
    jitter: AdaptiveJitterBuffer,
    stats: RtpStreamStats,
    dtmf_sender: DtmfSender,
    dtmf_detector: DtmfDetector,
    remote_ssrc: Option<u32>,
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

    /// Creates a [`MediaSession`] configured for any [`SessionCodec`] (G.711 or Opus).
    pub fn new_with_session_codec(
        codec: SessionCodec,
        dtmf_payload_type: u8,
        local_ssrc: u32,
        jitter_config: JitterBufferConfig,
    ) -> Self {
        let frame_samples = jitter_config.frame_samples.max(1);
        Self {
            codec,
            opus: Box::new(BuiltInOpusCodec::new()),
            dtmf_payload_type,
            frame_samples,
            packetizer: RtpPacketizer::new(local_ssrc, codec.payload_type(), 1, 0),
            jitter: AdaptiveJitterBuffer::new(jitter_config),
            stats: RtpStreamStats::new(),
            dtmf_sender: DtmfSender::new(),
            dtmf_detector: DtmfDetector::new(),
            remote_ssrc: None,
        }
    }

    /// Installs a custom [`OpusCodecBackend`] (such as native `LibOpusCodec`) using builder style.
    pub fn with_opus_backend(mut self, backend: Box<dyn OpusCodecBackend>) -> Self {
        self.opus = backend;
        self
    }

    /// Replaces the active [`OpusCodecBackend`].
    pub fn set_opus_backend(&mut self, backend: Box<dyn OpusCodecBackend>) {
        self.opus = backend;
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
        let (encoded, ts_advance) = match self.codec {
            SessionCodec::G711(kind) => {
                if self.frame_samples == PCM_FRAME_SAMPLES_48KHZ_20MS {
                    let pcm_8k = downsample_48k_to_8k(pcm);
                    (kind.encode(&pcm_8k), PCM_FRAME_SAMPLES_8KHZ_20MS as u32)
                } else {
                    (kind.encode(pcm), self.frame_samples as u32)
                }
            }
            SessionCodec::Opus { .. } => {
                let pkt = if self.frame_samples == PCM_FRAME_SAMPLES_48KHZ_20MS {
                    self.opus.encode_20ms_48khz(pcm)?
                } else {
                    self.opus.encode_20ms_8khz(pcm)?
                };
                (pkt, OPUS_RTP_SAMPLES_20MS)
            }
        };
        let pkt = self.packetizer.next_packet(encoded, ts_advance, false);
        Ok(pkt.to_bytes())
    }

    /// Queues an outbound RFC 4733 DTMF tone at the current media timestamp.
    pub fn queue_dtmf(&mut self, digit: DtmfDigit) {
        let ts = self.packetizer.current_timestamp();
        self.dtmf_sender.queue_digit(digit, ts);
    }

    /// Pops the next queued RFC 4733 DTMF RTP datagram for paced 20 ms transmission.
    pub fn pop_dtmf_packet(&mut self) -> Option<Vec<u8>> {
        self.dtmf_sender.pop_packet().map(|spec| {
            self.packetizer
                .build_custom_packet(
                    self.dtmf_payload_type,
                    spec.timestamp,
                    spec.marker,
                    spec.payload.to_bytes(),
                )
                .to_bytes()
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

    /// Processes an inbound RTP packet, updating RTCP stats and pushing decoded PCM or detecting DTMF.
    pub fn receive_rtp(
        &mut self,
        raw: &[u8],
        arrival_timestamp_samples: u32,
    ) -> Result<Option<DtmfDigit>, MediaError> {
        let pkt = RtpPacket::parse(raw)?;
        self.remote_ssrc = Some(pkt.header.ssrc);
        self.stats.record_packet(
            pkt.header.sequence_number,
            pkt.header.timestamp,
            arrival_timestamp_samples,
        );

        if pkt.header.payload_type == self.dtmf_payload_type {
            let ev = DtmfEventPayload::parse(&pkt.payload)?;
            return Ok(self.dtmf_detector.feed(pkt.header.timestamp, ev));
        }

        let pcm = if matches!(self.codec, SessionCodec::Opus { payload_type } if payload_type == pkt.header.payload_type)
        {
            if self.frame_samples == PCM_FRAME_SAMPLES_48KHZ_20MS {
                self.opus.decode_20ms_48khz(&pkt.payload)?
            } else {
                self.opus.decode_20ms_8khz(&pkt.payload)?
            }
        } else {
            let rx_codec =
                G711Kind::from_payload_type(pkt.header.payload_type).ok_or_else(|| {
                    MediaError::UnsupportedCodec(format!(
                        "unsupported RTP payload type {}",
                        pkt.header.payload_type
                    ))
                })?;
            let pcm_8k = rx_codec.decode(&pkt.payload);
            if self.frame_samples == PCM_FRAME_SAMPLES_48KHZ_20MS {
                upsample_8k_to_48k(&pcm_8k)
            } else {
                pcm_8k
            }
        };

        let rtp_samples_per_frame = self.codec.clock_rate_hz() / 50;
        let scaled_jitter =
            if rtp_samples_per_frame > 0 && rtp_samples_per_frame != self.frame_samples as u32 {
                ((u64::from(self.stats.jitter()) * u64::from(self.frame_samples as u32))
                    / u64::from(rtp_samples_per_frame)) as u32
            } else {
                self.stats.jitter()
            };

        self.jitter
            .push(pkt.header.sequence_number, pcm, scaled_jitter);
        Ok(None)
    }

    /// Pops the next 20 ms playout frame from the adaptive jitter buffer.
    pub fn pop_playout_frame(&mut self) -> PlayoutFrame {
        self.jitter.pop()
    }

    /// Builds an RTCP Receiver Report (`RR`) packet from current stream statistics.
    pub fn build_rtcp_receiver_report(&self) -> Vec<u8> {
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

#[cfg(test)]
mod tests {
    use super::*;
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
}
