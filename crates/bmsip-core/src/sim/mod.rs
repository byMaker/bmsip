//! MODULE_CONTRACT: Deterministic virtual UDP network simulator (`VirtualNetwork`) connecting two `TransactionManager` instances.
//! INVARIANTS: Zero real sockets or sleeps; deterministic Xorshift64 PRNG controls packet loss, duplication, and latency; virtual clock advances directly to earliest packet or timer deadline.
//! RFC_REFS: RFC 3261 Section 17 retransmission and timer verification harness.

use std::time::{Duration, Instant};

use crate::sip::message::SipMessage;
use crate::transaction::{RfcTimers, TransactionEvent, TransactionManager};

/// Simulated packet-loss, duplication, and latency parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkPolicy {
    /// Percentage of transmitted packets dropped (0..=100).
    pub loss_percent: u8,
    /// Percentage of surviving packets delivered twice (0..=100).
    pub duplicate_percent: u8,
    /// Minimum one-way propagation delay.
    pub min_delay: Duration,
    /// Maximum one-way propagation delay.
    pub max_delay: Duration,
}

impl Default for NetworkPolicy {
    fn default() -> Self {
        Self {
            loss_percent: 0,
            duplicate_percent: 0,
            min_delay: Duration::from_millis(10),
            max_delay: Duration::from_millis(40),
        }
    }
}

/// Network endpoint identifier inside [`VirtualNetwork`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointId {
    Client,
    Server,
}

#[derive(Debug, Clone)]
struct InFlightPacket {
    deliver_at: Instant,
    to: EndpointId,
    bytes: Vec<u8>,
}

/// Summary counters collected during a simulated network run.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SimStats {
    pub packets_sent: usize,
    pub packets_dropped: usize,
    pub packets_duplicated: usize,
    pub packets_delivered: usize,
    pub steps_executed: usize,
}

/// Events produced on a single virtual simulation step.
#[derive(Debug, Clone, Default)]
pub struct StepEvents {
    pub client_events: Vec<TransactionEvent>,
    pub server_events: Vec<TransactionEvent>,
}

/// Deterministic in-memory virtual UDP network connecting a client and server [`TransactionManager`].
#[derive(Debug)]
pub struct VirtualNetwork {
    now: Instant,
    pub client: TransactionManager,
    pub server: TransactionManager,
    in_flight: Vec<InFlightPacket>,
    policy: NetworkPolicy,
    rng_state: u64,
    pub stats: SimStats,
}

impl VirtualNetwork {
    /// Creates a new virtual network anchored at caller-supplied `start` instant.
    pub fn new(start: Instant, timers: RfcTimers, policy: NetworkPolicy, seed: u64) -> Self {
        Self {
            now: start,
            client: TransactionManager::new(timers),
            server: TransactionManager::new(timers),
            in_flight: Vec::new(),
            policy,
            rng_state: if seed == 0 {
                0x9e37_79b9_7f4a_7c15
            } else {
                seed
            },
            stats: SimStats::default(),
        }
    }

    /// Returns the current virtual clock timestamp.
    pub fn now(&self) -> Instant {
        self.now
    }

    /// Flushes newly queued outbound packets from both endpoints into the simulated network.
    pub fn enqueue_outbound(&mut self) {
        let client_pkts = self.client.poll_transmit();
        for pkt in client_pkts {
            self.schedule_packet(EndpointId::Server, pkt);
        }

        let server_pkts = self.server.poll_transmit();
        for pkt in server_pkts {
            self.schedule_packet(EndpointId::Client, pkt);
        }
    }

    /// Advances the virtual clock to the next packet delivery or timer deadline and processes it.
    ///
    /// Returns `None` when both endpoints have no pending timers and no in-flight packets remain.
    pub fn step(&mut self) -> Option<StepEvents> {
        self.enqueue_outbound();

        let next_packet_at = self.in_flight.iter().map(|p| p.deliver_at).min();
        let next_client_timer = self.client.poll_timeout();
        let next_server_timer = self.server.poll_timeout();

        let next_at = [next_packet_at, next_client_timer, next_server_timer]
            .into_iter()
            .flatten()
            .min()?;

        if next_at > self.now {
            self.now = next_at;
        }

        let mut step_events = StepEvents::default();

        // Deliver all packets due at `self.now`.
        let mut remaining = Vec::with_capacity(self.in_flight.len());
        let mut due = Vec::new();
        for pkt in self.in_flight.drain(..) {
            if pkt.deliver_at <= self.now {
                due.push(pkt);
            } else {
                remaining.push(pkt);
            }
        }
        self.in_flight = remaining;

        for pkt in due {
            self.stats.packets_delivered += 1;
            if let Ok(msg) = SipMessage::parse(&pkt.bytes) {
                match pkt.to {
                    EndpointId::Client => {
                        step_events
                            .client_events
                            .extend(self.client.receive_message(msg, self.now));
                    }
                    EndpointId::Server => {
                        step_events
                            .server_events
                            .extend(self.server.receive_message(msg, self.now));
                    }
                }
            }
        }

        // Fire due timeouts on both endpoints.
        step_events
            .client_events
            .extend(self.client.handle_timeout(self.now));
        step_events
            .server_events
            .extend(self.server.handle_timeout(self.now));

        self.enqueue_outbound();
        self.stats.steps_executed += 1;
        Some(step_events)
    }

    fn schedule_packet(&mut self, to: EndpointId, bytes: Vec<u8>) {
        self.stats.packets_sent += 1;
        if self.next_pct() < self.policy.loss_percent {
            self.stats.packets_dropped += 1;
            return;
        }

        let delay = self.next_delay();
        self.in_flight.push(InFlightPacket {
            deliver_at: self.now + delay,
            to,
            bytes: bytes.clone(),
        });

        if self.next_pct() < self.policy.duplicate_percent {
            self.stats.packets_duplicated += 1;
            let extra_delay = delay + Duration::from_millis(5);
            self.in_flight.push(InFlightPacket {
                deliver_at: self.now + extra_delay,
                to,
                bytes,
            });
        }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.rng_state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.rng_state = x;
        x
    }

    fn next_pct(&mut self) -> u8 {
        (self.next_u64() % 100) as u8
    }

    fn next_delay(&mut self) -> Duration {
        let min_ms = self.policy.min_delay.as_millis() as u64;
        let max_ms = self.policy.max_delay.as_millis().max(min_ms as u128) as u64;
        if max_ms == min_ms {
            return Duration::from_millis(min_ms);
        }
        let span = max_ms - min_ms + 1;
        Duration::from_millis(min_ms + (self.next_u64() % span))
    }
}
