//! FFI 边界的 async 桥：lazy 全局 tokio 运行时。
//!
//! PersonaService/Emitter/Database 都是 async（sqlx 需要 reactor），而
//! extern "C" 函数是同步的——每个 FFI 入口统一走 [`block_on`] 把异步
//! 调用压成同步；Emitter `start()` 的后台 flush 任务与 sqlx 连接池都挂
//! 在这个运行时上。
//!
//! 注意：本 crate 的测试**必须用 `#[test]` 而非 `#[tokio::test]`**——
//! 在 tokio 运行时上下文里再 `block_on` 会被拒绝（嵌套运行时 panic）。

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

/// 在全局 FFI 运行时上执行异步代码（阻塞调用线程直至完成）。
pub(crate) fn block_on<F: Future>(future: F) -> F::Output {
    runtime().block_on(future)
}
