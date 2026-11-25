//! Client-side audit event reporter.
//!
//! The local sqlite audit database (`AuditLogRepository`) is the durable
//! source of record; [`Emitter`] is only best-effort async replication:
//! an in-memory queue + batched POST + exponential backoff. A process
//! crash loses the unflushed in-memory batch and nothing is replayed (no
//! durable outbox).
//!
//! Wiring: `PersonaService::set_event_emitter`; the reporting destination
//! implements [`EventSink`] (the persona-server implementation is
//! `ServerEventSink`, requiring the `events-server` feature).

pub mod emitter;
#[cfg(feature = "events-server")]
pub mod server_sink;
pub mod wire;

pub use emitter::*;
#[cfg(feature = "events-server")]
pub use server_sink::*;
pub use wire::*;

/// FakeSink and waiting helpers shared by Emitter unit tests (visible to #[cfg(test)] modules across this crate).
#[cfg(test)]
pub(crate) mod testing;
