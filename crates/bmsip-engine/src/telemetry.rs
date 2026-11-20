//! MODULE_CONTRACT: Bounded ring-buffer telemetry and per-call structured flight recorder ("black box") with dependency-free JSON export.
//! INVARIANTS: Never stores authentication secrets or passwords; bounds global entry count (`capacity`); preserves per-call black-box snapshots across call termination.
//! RFC_REFS: RFC 3261, RFC 3550.

use std::collections::{HashMap, VecDeque};
use std::fmt::Write;
use std::time::Instant;

/// Telemetry entry category recorded by [`FlightRecorder`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TelemetryCategory {
    SipRx,
    SipTx,
    DialogFsm,
    RegistrationFsm,
    RtpStats,
    Lifecycle,
    Warning,
}

impl TelemetryCategory {
    /// Returns the JSON string label for this category.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SipRx => "sip_rx",
            Self::SipTx => "sip_tx",
            Self::DialogFsm => "dialog_fsm",
            Self::RegistrationFsm => "registration_fsm",
            Self::RtpStats => "rtp_stats",
            Self::Lifecycle => "lifecycle",
            Self::Warning => "warning",
        }
    }
}

/// Single timestamped diagnostic event inside the flight recorder ring buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelemetryEntry {
    pub seq: u64,
    pub elapsed_ms: u64,
    pub category: TelemetryCategory,
    pub call_id: Option<String>,
    pub summary: String,
}

/// Per-call diagnostic summary ("black box") exported on call termination or on demand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallBlackBoxSnapshot {
    pub call_id: String,
    pub direction: String,
    pub final_state: String,
    pub rtp_packets_sent: u32,
    pub rtp_packets_received: u32,
    pub rtp_packets_lost: i32,
    pub rtp_jitter_samples: u32,
    pub dtmf_digits_received: Vec<char>,
    pub events: Vec<TelemetryEntry>,
}

impl CallBlackBoxSnapshot {
    /// Serializes this snapshot to JSON without external dependencies.
    pub fn to_json(&self) -> String {
        let mut out = String::with_capacity(512);
        out.push('{');
        let _ = write!(
            out,
            "\"call_id\":{},\"direction\":{},\"final_state\":{},\"rtp_packets_sent\":{},\"rtp_packets_received\":{},\"rtp_packets_lost\":{},\"rtp_jitter_samples\":{},\"dtmf_digits_received\":[",
            json_string(&self.call_id),
            json_string(&self.direction),
            json_string(&self.final_state),
            self.rtp_packets_sent,
            self.rtp_packets_received,
            self.rtp_packets_lost,
            self.rtp_jitter_samples
        );
        for (i, ch) in self.dtmf_digits_received.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str(&json_string(&ch.to_string()));
        }
        out.push_str("],\"events\":[");
        for (i, ev) in self.events.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            write_entry_json(&mut out, ev);
        }
        out.push_str("]}");
        out
    }
}

#[derive(Debug, Clone)]
struct ActiveCallTrace {
    direction: String,
    rtp_packets_sent: u32,
    rtp_packets_received: u32,
    rtp_packets_lost: i32,
    rtp_jitter_samples: u32,
    dtmf_digits_received: Vec<char>,
    events: Vec<TelemetryEntry>,
}

/// Bounded ring-buffer telemetry recorder and per-call flight recorder.
#[derive(Debug)]
pub struct FlightRecorder {
    started_at: Instant,
    capacity: usize,
    next_seq: u64,
    ring: VecDeque<TelemetryEntry>,
    active_calls: HashMap<String, ActiveCallTrace>,
    finished_calls: HashMap<String, CallBlackBoxSnapshot>,
    finished_order: VecDeque<String>,
}

impl FlightRecorder {
    /// Creates a [`FlightRecorder`] anchored at `started_at` with ring `capacity`.
    pub fn new(started_at: Instant, capacity: usize) -> Self {
        Self {
            started_at,
            capacity: capacity.max(16),
            next_seq: 1,
            ring: VecDeque::new(),
            active_calls: HashMap::new(),
            finished_calls: HashMap::new(),
            finished_order: VecDeque::new(),
        }
    }

    /// Initializes per-call tracking when a call starts or arrives.
    pub fn begin_call(&mut self, call_id: &str, direction: &str) {
        self.active_calls
            .entry(call_id.to_string())
            .or_insert_with(|| ActiveCallTrace {
                direction: direction.to_string(),
                rtp_packets_sent: 0,
                rtp_packets_received: 0,
                rtp_packets_lost: 0,
                rtp_jitter_samples: 0,
                dtmf_digits_received: Vec::new(),
                events: Vec::new(),
            });
    }

    /// Records a timestamped diagnostic event into the global ring buffer and optional call trace.
    pub fn record(
        &mut self,
        now: Instant,
        category: TelemetryCategory,
        call_id: Option<&str>,
        summary: impl Into<String>,
    ) {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);
        let elapsed_ms = now.saturating_duration_since(self.started_at).as_millis() as u64;

        let entry = TelemetryEntry {
            seq,
            elapsed_ms,
            category,
            call_id: call_id.map(str::to_string),
            summary: summary.into(),
        };

        if self.ring.len() >= self.capacity {
            self.ring.pop_front();
        }
        self.ring.push_back(entry.clone());

        if let Some(cid) = call_id {
            if let Some(trace) = self.active_calls.get_mut(cid) {
                if trace.events.len() < self.capacity {
                    trace.events.push(entry);
                }
            }
        }
    }

    /// Records a received DTMF digit for `call_id`.
    pub fn record_dtmf(&mut self, call_id: &str, digit: char) {
        if let Some(trace) = self.active_calls.get_mut(call_id) {
            trace.dtmf_digits_received.push(digit);
        }
    }

    /// Updates live RTP statistics on an active call trace.
    pub fn update_rtp_stats(
        &mut self,
        call_id: &str,
        packets_sent: u32,
        packets_received: u32,
        packets_lost: i32,
        jitter_samples: u32,
    ) {
        if let Some(trace) = self.active_calls.get_mut(call_id) {
            trace.rtp_packets_sent = packets_sent;
            trace.rtp_packets_received = packets_received;
            trace.rtp_packets_lost = packets_lost;
            trace.rtp_jitter_samples = jitter_samples;
        }
    }

    /// Finalizes a call trace, returning its [`CallBlackBoxSnapshot`] and retaining it for later queries.
    pub fn finish_call(
        &mut self,
        call_id: &str,
        final_state: &str,
        packets_sent: u32,
        packets_received: u32,
        packets_lost: i32,
        jitter_samples: u32,
    ) -> CallBlackBoxSnapshot {
        let trace = self.active_calls.remove(call_id);
        let snapshot = match trace {
            Some(t) => CallBlackBoxSnapshot {
                call_id: call_id.to_string(),
                direction: t.direction,
                final_state: final_state.to_string(),
                rtp_packets_sent: packets_sent.max(t.rtp_packets_sent),
                rtp_packets_received: packets_received.max(t.rtp_packets_received),
                rtp_packets_lost: packets_lost,
                rtp_jitter_samples: jitter_samples,
                dtmf_digits_received: t.dtmf_digits_received,
                events: t.events,
            },
            None => CallBlackBoxSnapshot {
                call_id: call_id.to_string(),
                direction: "unknown".to_string(),
                final_state: final_state.to_string(),
                rtp_packets_sent: packets_sent,
                rtp_packets_received: packets_received,
                rtp_packets_lost: packets_lost,
                rtp_jitter_samples: jitter_samples,
                dtmf_digits_received: Vec::new(),
                events: Vec::new(),
            },
        };

        if self.finished_order.len() >= 32 {
            if let Some(evicted) = self.finished_order.pop_front() {
                self.finished_calls.remove(&evicted);
            }
        }
        self.finished_order.push_back(call_id.to_string());
        self.finished_calls
            .insert(call_id.to_string(), snapshot.clone());
        snapshot
    }

    /// Serializes the entire engine telemetry ring buffer to JSON.
    pub fn to_json(&self) -> String {
        let mut out = String::with_capacity(512);
        out.push_str("{\"events\":[");
        for (i, ev) in self.ring.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            write_entry_json(&mut out, ev);
        }
        out.push_str("]}");
        out
    }

    /// Serializes a specific active or recently terminated call's black-box snapshot to JSON.
    pub fn call_to_json(&self, call_id: &str) -> String {
        if let Some(snap) = self.finished_calls.get(call_id) {
            return snap.to_json();
        }
        if let Some(trace) = self.active_calls.get(call_id) {
            let snap = CallBlackBoxSnapshot {
                call_id: call_id.to_string(),
                direction: trace.direction.clone(),
                final_state: "active".to_string(),
                rtp_packets_sent: trace.rtp_packets_sent,
                rtp_packets_received: trace.rtp_packets_received,
                rtp_packets_lost: trace.rtp_packets_lost,
                rtp_jitter_samples: trace.rtp_jitter_samples,
                dtmf_digits_received: trace.dtmf_digits_received.clone(),
                events: trace.events.clone(),
            };
            return snap.to_json();
        }
        format!("{{\"call_id\":{},\"events\":[]}}", json_string(call_id))
    }
}

fn write_entry_json(out: &mut String, ev: &TelemetryEntry) {
    out.push('{');
    let _ = write!(
        out,
        "\"seq\":{},\"elapsed_ms\":{},\"category\":{},",
        ev.seq,
        ev.elapsed_ms,
        json_string(ev.category.as_str())
    );
    match &ev.call_id {
        Some(cid) => {
            let _ = write!(out, "\"call_id\":{},", json_string(cid));
        }
        None => out.push_str("\"call_id\":null,"),
    }
    let _ = write!(out, "\"summary\":{}", json_string(&ev.summary));
    out.push('}');
}

fn json_string(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 2);
    out.push('"');
    for ch in input.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn flight_recorder_bounds_ring_and_exports_call_json() {
        let t0 = Instant::now();
        let mut rec = FlightRecorder::new(t0, 16);
        rec.begin_call("c1", "outbound");
        for i in 0..25 {
            rec.record(
                t0 + Duration::from_millis(i * 10),
                TelemetryCategory::SipTx,
                Some("c1"),
                format!("msg {i}"),
            );
        }
        rec.record_dtmf("c1", '5');
        let snap = rec.finish_call("c1", "terminated", 12, 10, 0, 4);
        let json = snap.to_json();
        assert!(json.contains("\"call_id\":\"c1\""));
        assert!(json.contains("\"rtp_packets_sent\":12"));
        assert!(json.contains("\"rtp_packets_received\":10"));
        assert!(json.contains("\"dtmf_digits_received\":[\"5\"]"));
        assert!(rec.to_json().contains("\"events\":["));
    }
}
