//! MODULE_CONTRACT: Cross-platform FFI facade (`bmsip-ffi`) exposing UniFFI-compatible safe Rust SDK (`client`) and C99 ABI (`c_api`).
//! INVARIANTS: `client` enforces `#![forbid(unsafe_code)]`; `c_api` isolates raw pointer validation with explicit null checks and panic-free boundaries.
//! RFC_REFS: RFC 3261, RFC 3550, RFC 4733, RFC 7587.

pub mod c_api;
pub mod client;

pub use bmsip_engine;
pub use c_api::{
    bmsip_client_answer, bmsip_client_dial, bmsip_client_free, bmsip_client_hangup,
    bmsip_client_new, bmsip_client_notify_network_changed, bmsip_client_poll_event_json,
    bmsip_client_pop_pcm, bmsip_client_push_pcm, bmsip_client_register, bmsip_client_resume,
    bmsip_client_ring, bmsip_client_send_dtmf, bmsip_client_suspend, bmsip_client_unregister,
    bmsip_string_free, BmsipClientHandle,
};
pub use client::{BmsipClient, FfiConfig, FfiError, FfiEvent, FfiEventKind};
