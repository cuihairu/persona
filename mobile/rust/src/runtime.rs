//! Async bridge at the FFI boundary: a lazy global tokio runtime.
//!
//! PersonaService/Emitter/Database are all async (sqlx needs a reactor), while
//! the `extern "C"` functions are synchronous — every FFI entry point funnels
//! through [`block_on`] to force the async call into a sync one; the Emitter
//! `start()` background flush task and the sqlx connection pool both hang off
//! this runtime.
//!
//! Note: tests in this crate **must use `#[test]` rather than `#[tokio::test]`**
//! — calling `block_on` inside a tokio runtime context is rejected (nested
//! runtime panic).

use std::future::Future;
use std::sync::OnceLock;
use tokio::runtime::Runtime;

static RUNTIME: OnceLock<Runtime> = OnceLock::new();

fn runtime() -> &'static Runtime {
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("failed to build tokio runtime for FFI bridge")
    })
}

/// Run async code on the global FFI runtime (blocks the calling thread until completion).
pub(crate) fn block_on<F: Future>(future: F) -> F::Output {
    runtime().block_on(future)
}
