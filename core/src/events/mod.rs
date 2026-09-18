//! 客户端审计事件上报器。
//!
//! 本地 sqlite 审计库（`AuditLogRepository`）是持久存证源；[`Emitter`]
//! 只是尽力而为的异步复制：内存队列 + 批量 POST + 指数退避，进程崩溃
//! 即丢未 flush 的内存批，不回补（无持久 outbox）。
//!
//! 接入方式：`PersonaService::set_event_emitter`；上报目的地实现
//! [`EventSink`]（persona-server 的实现见 `ServerEventSink`，需
//! `events-server` feature）。

pub mod emitter;
#[cfg(feature = "events-server")]
pub mod server_sink;
pub mod wire;

pub use emitter::*;
#[cfg(feature = "events-server")]
pub use server_sink::*;
pub use wire::*;

/// Emitter 单测共享的 FakeSink 与等待辅助（同 crate 各模块 #[cfg(test)] 可见）。
#[cfg(test)]
pub(crate) mod testing;
