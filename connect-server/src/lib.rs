//! Connect 本机自动化 HTTP 端点（CONNECT_AUTOMATION_DESIGN DR-1/DR-3/DR-4）。
//!
//! 独立 crate：桌面（DR-1 A1）与 CLI `persona connect serve`（A2）
//! 两个宿主共用同一 router/三防线/限额实现与同一 core 服务层——
//! token 存储（工作区库内 `connect_tokens` 表）跨宿主天然互通。
//! 其余语义见下（模块文档自 desktop 迁移时保持原样）。
//!
//! listener 内嵌在宿主进程内，双传输（[`ConnectTransport`]）：
//! - **TCP loopback**（默认）：bind 硬编码 `127.0.0.1`（端口 0 = OS 分配；
//!   地址无配置面，「拒绝非 loopback 配置」由硬编码天然满足）。
//! - **Unix domain socket**（`--unix-socket`，仅 unix 平台）：socket 文件
//!   0600 + accept 层 peer-uid 校验（连不上 ≠ 能通过，uid 不符连接即被丢弃），
//!   无 TCP 端口；Windows 无此传输，创建即报错。
//!
//! 默认关闭：不开启 = 不创建 listener。
//!
//! 请求管线（每请求）：
//! 1. Host 头白名单（`127.0.0.1`/`localhost`）→ 否则 421（DNS rebinding）。
//!    **仅 TCP**：unix socket 无名字解析面，DNS rebinding 不可达，跳过该检查
//!    （客户端可发任意 Host，如 Go 生态常用的 `http://unix/…`）。
//! 2. `Origin` 头出现即 403（本机 API 无合法浏览器跨源消费者，CORS 全关）
//! 3. `/health` 免认证零信息；其余要求 `Authorization: Bearer pconn_…`
//! 4. token 哈希查库（吊销/未知同形 401，无缓存窗口）
//! 5. 锁定门禁：未解锁 → 503 `vault_locked`，**不消耗**限额（锁屏重试
//!    风暴不锁死 token）
//! 6. 限额：每 token 每分钟 120 请求（固定窗，超限 429；上限写死）
//! 7. 数据面 scope 过滤（core `connect_*`），scope 外/归档/不存在同形 404
//!
//! 响应一律 `{"ok":…}` 包络（错误 `{"ok":false,"error":{"code","message"}}`，
//! 与 server 包络形状对齐）+ `Cache-Control: no-store`（TOTP 码与字段
//! 明文不进任何中间缓存）。scope 判定与 token 生命周期在 core
//! （`persona_core::connect`），本模块只做 HTTP 面编排。

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::middleware::{self};
use axum::routing::{get, post};
use axum::Router;
use persona_core::PersonaService;
use tokio::sync::Mutex as TokioMutex;
use uuid::Uuid;

/// 每 token 每分钟请求数上限（DR-3：固定窗；上限写死不做配置——
/// 配置面越大误用面越大）。
pub const RATE_LIMIT_PER_MINUTE: u32 = 120;

const RATE_WINDOW: Duration = Duration::from_secs(60);
/// 速率表清扫阈值：达到该槽位数时清一次窗口已过期的死槽位（token 删除
/// /更换后的残留条目，慢泄漏上界封顶，audit 批2 #10）。只在每这么多
/// token 记账时触发一次，O(n) 摊还成本恒定。
const RATE_SWEEP_THRESHOLD: usize = 16;

/// `Arc<tokio::sync::Mutex<Option<PersonaService>>>` 别名（与 AppState
/// 的 service 字段同型，命令层 clone 传入）。
pub type ArcTokService = Arc<TokioMutex<Option<PersonaService>>>;

/// Connect listener 的传输层。
///
/// - [`ConnectTransport::Tcp`]：loopback TCP（默认；`port` 0 = OS 分配真实端口）。
/// - [`ConnectTransport::Unix`]：unix domain socket（仅 unix 平台可创建成功；
///   Windows 上 [`start_connect_server_with_transport`] 直接报错——tokio 无
///   Windows UnixListener，named pipe 形态是后续议题而非本传输的等价物）。
#[derive(Clone, Debug)]
pub enum ConnectTransport {
    /// loopback TCP：`127.0.0.1:{port}`（port 0 = OS 分配）。
    Tcp { port: u16 },
    /// unix domain socket：0600 文件权限 + accept 层属主 uid 校验。
    Unix { path: PathBuf },
}

mod endpoints;
mod guard;
mod unix;

#[cfg(test)]
use axum::http::header;
#[cfg(test)]
use axum::response::Response;
use endpoints::{health, identities, item, item_totp, items};
#[cfg(test)]
use endpoints::{internal_or_locked, item_meta_json, item_type_slug, locked_response};
use guard::guard;
#[cfg(test)]
use guard::{err_json, is_vault_locked, ok_json};
#[cfg(test)]
use persona_core::PersonaError;
#[cfg(test)]
use serde_json::json;
#[cfg(unix)]
use unix::UidCheckedListener;
#[cfg(all(test, unix))]
use unix::{peer_allowed, Accept};

#[derive(Clone)]
pub struct ConnectServerState {
    /// 与 AppState 共享的同一 service 槽位（token 校验 + 解锁态门禁）。
    pub service: ArcTokService,
    /// 每 token 固定窗计数：token id → (窗口起点, 已计请求数)。纯内存、
    /// 进程重启即清——这是宿主保护（防失控轮询拖垮宿主），不是审计。
    rates: Arc<Mutex<HashMap<Uuid, (Instant, u32)>>>,
    /// Host 头白名单（`127.0.0.1`/`localhost`/`::1`）是否强制。
    ///
    /// 该防线针对 DNS rebinding：域名解析到本机 IP + 恶意 Host 打到 loopback
    /// 端口。unix socket 没有名字解析面（连接打到文件路径，浏览器/域名解析
    /// 不可达），白名单无防护对象、只剩误拒合法客户端的成本（Go 生态常用
    /// `Host: unix` 之类的任意值），故 unix 传输跳过；`Origin`/token/限额
    /// 三条防线在两种传输上原样生效。
    require_loopback_host: bool,
}

impl ConnectServerState {
    pub fn new(service: ArcTokService) -> Self {
        Self {
            service,
            rates: Arc::new(Mutex::new(HashMap::new())),
            require_loopback_host: true,
        }
    }

    /// unix 传输的 state：跳过 Host 白名单（理由见字段文档）。
    #[cfg(unix)]
    fn new_unix(service: ArcTokService) -> Self {
        Self {
            require_loopback_host: false,
            ..Self::new(service)
        }
    }

    /// 固定窗计数：窗口过期则重置为 1；未过期且已满返回 false（429）。
    fn consume_rate(&self, token_id: Uuid) -> bool {
        let mut rates = self.rates.lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        // 低频清扫：达到阈值时清掉窗口已过期的死槽位，慢泄漏上界封顶。
        // 阈值内（正常低基数部署）不触发，避免每请求 O(n) 全表扫。
        if rates.len() >= RATE_SWEEP_THRESHOLD {
            rates.retain(|_, (window_start, _)| now.duration_since(*window_start) < RATE_WINDOW);
        }
        let slot = rates.entry(token_id).or_insert((now, 0));
        if now.duration_since(slot.0) >= RATE_WINDOW {
            *slot = (now, 1);
            return true;
        }
        if slot.1 >= RATE_LIMIT_PER_MINUTE {
            return false;
        }
        slot.1 += 1;
        true
    }
}

/// 组装路由 + 三防线/认证/限额 middleware。测试与生产共用（生产经
/// [`start_connect_server`] bind，测试经 `Router::oneshot` 无网络直驱）。
pub fn build_router(state: ConnectServerState) -> Router {
    Router::new()
        .route("/api/v1/connect/health", get(health))
        .route("/api/v1/connect/identities", get(identities))
        .route("/api/v1/connect/items", get(items))
        .route("/api/v1/connect/items/{id}", get(item))
        .route("/api/v1/connect/items/{id}/totp", post(item_totp))
        .layer(middleware::from_fn_with_state(state.clone(), guard))
        .with_state(state)
}

/// 启动 Connect listener（loopback TCP，兼容入口）。
///
/// 等价于 [`start_connect_server_with_transport`] + [`ConnectTransport::Tcp`]。
/// 返回句柄（实际端口 + 关停通道）；bind 失败（端口被占等）向上传播给调用方
/// （设置页显式报错，不静默重试）。
pub async fn start_connect_server(
    service: ArcTokService,
    port: u16,
) -> anyhow::Result<ConnectServerHandle> {
    start_connect_server_with_transport(service, ConnectTransport::Tcp { port }).await
}

/// 按指定传输启动 Connect listener，返回句柄（TCP：实际端口；unix：
/// socket 路径）+ 关停通道。bind 失败向上传播，不静默重试。
///
/// - [`ConnectTransport::Tcp`]：`127.0.0.1:{port}`（0 = OS 分配）。
/// - [`ConnectTransport::Unix`]：0600 socket 文件 + accept 层属主 uid 校验
///   （陈旧残骸接管、活 listener 一律报错不劫持，口径同 ssh-agent transport）。
///   非 unix 平台（Windows）直接报错——见 [`ConnectTransport`] 文档。
pub async fn start_connect_server_with_transport(
    service: ArcTokService,
    transport: ConnectTransport,
) -> anyhow::Result<ConnectServerHandle> {
    match transport {
        ConnectTransport::Tcp { port } => {
            let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
            let listener = tokio::net::TcpListener::bind(addr).await?;
            let actual_port = listener.local_addr()?.port();
            let router = build_router(ConnectServerState::new(service));
            let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
            let closed = tokio::spawn(async move {
                let _ = axum::serve(listener, router)
                    .with_graceful_shutdown(async {
                        let _ = shutdown_rx.await;
                    })
                    .await;
            });
            Ok(ConnectServerHandle {
                port: actual_port,
                socket_path: None,
                shutdown: shutdown_tx,
                closed,
            })
        }
        ConnectTransport::Unix { path } => {
            #[cfg(unix)]
            {
                start_unix(service, path).await
            }
            #[cfg(not(unix))]
            {
                let _ = (service, path);
                // Windows 上 tokio 没有 UnixListener（AF_UNIX 不可移植到本 crate
                // 的支持面）；named pipe 是另一传输形态，不在此冒充。显式报错，
                // 调用方（CLI --unix）拿到可执行的替代指引。
                anyhow::bail!(
                    "unix socket transport is not supported on this platform; \
                     use TCP loopback instead (`persona connect serve` without --unix)"
                )
            }
        }
    }
}

/// unix 传输实现（仅 unix 平台编译）。
///
/// 三层本地防护：① socket 文件 0600（bind 后立即收紧，防 umask 残留组/
/// 其他位）；② accept 层属主 uid 校验（[`UidCheckedListener`]——文件权限
/// 是内核层，uid 校验兜住权限位被改动/异常场景，fail-closed）；③ HTTP 层
/// token 认证（两种传输相同）。`Origin`/限额原样生效，Host 白名单跳过
/// （见 [`ConnectServerState::require_loopback_host`]）。
#[cfg(unix)]
async fn start_unix(service: ArcTokService, path: PathBuf) -> anyhow::Result<ConnectServerHandle> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }

    // 先 bind，不预先删除（TOCTOU：exists→remove→bind 之间路径可能被换掉）。
    // 只有确认旧路径是陈旧残骸（非 socket 或无人监听）才接管；活着的 listener
    // 一律报错而非静默劫持路径（口径同 ssh-agent transport::bind，实现收口
    // 在 persona_core::socket::is_stale_socket）。
    let listener = match tokio::net::UnixListener::bind(&path) {
        Ok(listener) => listener,
        Err(err) => {
            // 用 symlink_metadata 判「路径名被占用」：存在断链 symlink 时
            // Path::exists() 跟随链接为 false 会漏掉可接管的残骸。
            if path.symlink_metadata().is_err() {
                anyhow::bail!("failed to bind connect socket {}: {err}", path.display());
            }
            if !persona_core::socket::is_stale_socket(&path) {
                anyhow::bail!(
                    "connect socket {} already bound by a live process: {err}",
                    path.display()
                );
            }
            std::fs::remove_file(&path)?;
            tokio::net::UnixListener::bind(&path)?
        }
    };

    // 0600：bind 创建的 socket 文件权限 = 0777 & ~umask（常见 umask 022 →
    // 0755，group/other 可见）。立即收紧到仅属主可连（unix socket 连接需要
    // 写权限，0600 即同用户独占——内核层）。
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    // 属主 = 刚 bind 成功的本进程用户（新鲜文件或接管后重建，见上）。
    let owner_uid = std::fs::metadata(&path)?.uid();

    let listener = UidCheckedListener {
        inner: listener,
        owner_uid,
    };
    let router = build_router(ConnectServerState::new_unix(service));
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let cleanup = path.clone();
    let closed = tokio::spawn(async move {
        let _ = axum::serve(listener, router)
            .with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            })
            .await;
        // 正常关停：移除 socket 文件（崩溃残骸由下一次启动按陈旧接管处理）。
        let _ = std::fs::remove_file(&cleanup);
    });
    Ok(ConnectServerHandle {
        port: 0,
        socket_path: Some(path),
        shutdown: shutdown_tx,
        closed,
    })
}

/// 运行中 listener 的句柄。
#[derive(Debug)]
pub struct ConnectServerHandle {
    /// listener 实际绑定端口（TCP 传输，端口 0 = OS 分配后的真实值）。
    /// **unix 传输恒为 0**（没有 TCP 端口；端点见 [`Self::socket_path`]）。
    pub port: u16,
    /// unix 传输的 socket 路径（TCP 传输为 `None`）。
    ///
    /// 正常关停后 socket 文件已移除；进程崩溃留下的残骸由下一次启动按
    /// 陈旧接管（`persona_core::socket::is_stale_socket`）处理。
    pub socket_path: Option<PathBuf>,
    shutdown: tokio::sync::oneshot::Sender<()>,
    /// listener 任务的收尾凭证（serve 循环结束 + socket 文件清理都在其内）。
    closed: tokio::task::JoinHandle<()>,
}

impl ConnectServerHandle {
    /// 触发 graceful shutdown（同步发送；listener 任务自行收尾）。
    ///
    /// fire-and-forget：调用方**不等清理完成**。进程随后立即退出时 runtime
    /// 会直接丢弃未跑完的清理任务（unix 下留陈旧 socket，靠下次启动接管
    /// 自愈）——进程退出路径请用 [`Self::stop_and_wait`]。
    pub fn stop(self) {
        let _ = self.shutdown.send(());
    }

    /// 触发 graceful shutdown 并等待 listener 任务完成（含 socket 文件移除）。
    ///
    /// 进程退出前的正确收尾：`closed` 完成即保证端口/socket 已释放，不留
    /// 竞态窗口（fire-and-forget 的 stop 在随后的进程退出下不保证清理）。
    pub async fn stop_and_wait(self) {
        let _ = self.shutdown.send(());
        let _ = self.closed.await;
    }
}

// -----------------------------------------------------------------------
// 包络与错误映射
// -----------------------------------------------------------------------

#[cfg(test)]
mod tests;
