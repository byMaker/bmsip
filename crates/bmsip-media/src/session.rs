//! MODULE_CONTRACT: Unified Sans-I/O 20 ms PCM <-> RTP/RTCP/DTMF media session pipeline (`MediaSession`).
//! INVARIANTS: Zero OS audio or socket APIs; operates strictly on byte slices and 20 ms `i16` PCM frames; routes DTMF payload type to `DtmfDetector` and G.711 payload types to `AdaptiveJitterBuffer`.
//! RFC_REFS: RFC 3550, RFC 3551, RFC 4733.

use crate::codec::G711Kind;
use crate::dtmf::{DtmfDetector, DtmfDigit, DtmfEventPayload, DtmfSender};
use crate::error::MediaError;
use crate::jitter::{AdaptiveJitterBuffer, JitterBufferConfig, PlayoutFrame};
use crate::rtcp::{RtcpPacket, RtpStreamStats};
use crate::rtp::{RtpPacket, RtpPacketizer};

/// Integrated Sans-I/O audio media pipeline combining packetizer, G.711 codec, DTMF, jitter buffer, and RTCP stats.
#[derive(Debug)]
pub struct MediaSession {
    codec: G711Kind,
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
    /// Creates a [`MediaSession`] configured for `codec` and `dtmf_payload_type`.
    pub fn new(
        codec: G711Kind,
        dtmf_payload_type: u8,
        local_ssrc: u32,
        jitter_config: JitterBufferConfig,
    ) -> Self {
        let frame_samples = jitter_config.frame_samples.max(1);
        Self {
            codec,
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

    /// Encodes one 20 ms mono PCM frame into an outbound RTP datagram.
    pub fn encode_pcm_frame(&mut self, pcm: &[i16]) -> Result<Vec<u8>, MediaError> {
        if pcm.len() != self.frame_samples {
            return Err(MediaError::BufferError(format!(
                "expected {} PCM samples, got {}",
                self.frame_samples,
                pcm.len()
            )));
        }
        let encoded = self.codec.encode(pcm);
        let pkt = self
            .packetizer
            .next_packet(encoded, self.frame_samples as u32, false);
        Ok(pkt.to_bytes())
    }

    /// Queues an outbound RFC 4733 DTMF tone at the current media timestamp.
    pub fn queue_dtmf(&mut self, digit: DtmfDigit) {
        let ts = self.packetizer.current_timestamp();
        self.dtmf_sender.queue_digit(digit, ts);
    }

    /// Drains queued outbound RFC 4733 DTMF RTP datagrams.
    pub fn poll_dtmf_packets(&mut self) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        while let Some(spec) = self.dtmf_sender.pop_packet() {
            let pkt = self.packetizer.build_custom_packet(
                self.dtmf_payload_type,
                spec.timestamp,
                spec.marker,
                spec.payload.to_bytes(),
            );
            out.push(pkt.to_bytes());
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

        let rx_codec = G711Kind::from_payload_type(pkt.header.payload_type).ok_or_else(|| {
            MediaError::UnsupportedCodec(format!(
                "unsupported RTP payload type {}",
                pkt.header.payload_type
            ))
        })?;
        let pcm = rx_codec.decode(&pkt.payload);
        self.jitter
            .push(pkt.header.sequence_number, pcm, self.stats.jitter());
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
}
