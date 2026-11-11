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

#[cfg(unix)]
use std::time::Duration;

/// accept 层属主 uid 校验的 unix listener 包装（仅 unix 平台）。
///
/// 每个新连接先取 `SO_PEERCRED`：uid 与 socket 文件属主一致才交付给 axum，
/// 不一致（其他用户、异常凭据）直接丢弃连接继续 accept——fail-closed，
/// 不消耗 HTTP 层任何状态。校验放在 accept 而非 middleware：被拒连接
/// 根本不进入 HTTP 解析面。
#[cfg(unix)]
pub(super) struct UidCheckedListener<L = tokio::net::UnixListener> {
    pub(super) inner: L,
    /// socket 文件属主 uid（= 本进程 uid，bind 时读取）。
    pub(super) owner_uid: u32,
}

/// [`UidCheckedListener`] 的内层 accept 抽象（可测性缝，仅 unix 平台）。
///
/// 固定产出 tokio `UnixStream`/`unix::SocketAddr`（peer 校验需要
/// `peer_cred`），错误按 `io::Result` 上抛——真实实现是 tokio
/// `UnixListener` 的固有方法，测试实现可注入错误序列。
#[cfg(unix)]
#[cfg(unix)]
pub(super) trait Accept: Send + 'static {
    fn accept(
        &mut self,
    ) -> impl std::future::Future<
        Output = std::io::Result<(tokio::net::UnixStream, tokio::net::unix::SocketAddr)>,
    > + Send;

    fn local_addr(&self) -> std::io::Result<tokio::net::unix::SocketAddr>;
}

#[cfg(unix)]
#[cfg(unix)]
impl Accept for tokio::net::UnixListener {
    async fn accept(
        &mut self,
    ) -> std::io::Result<(tokio::net::UnixStream, tokio::net::unix::SocketAddr)> {
        tokio::net::UnixListener::accept(self).await
    }

    fn local_addr(&self) -> std::io::Result<tokio::net::unix::SocketAddr> {
        tokio::net::UnixListener::local_addr(self)
    }
}

/// peer uid 判定纯函数（仅 unix 平台）：peer uid 是否与 socket 属主一致。
///
/// 自由函数而非 inherent 方法——[`UidCheckedListener`] 泛型化后，
/// 测试不必为一次纯比较标注实例类型。
#[cfg(unix)]
#[cfg(unix)]
pub(super) fn peer_allowed(peer_uid: u32, owner_uid: u32) -> bool {
    peer_uid == owner_uid
}

#[cfg(unix)]
#[cfg(unix)]
impl<L> UidCheckedListener<L>
where
    L: Accept,
{
    /// peer 凭据判定：`Ok` 且 uid == 属主 → 放行；mismatch / 取不到凭据 →
    /// 拒（各自留痕后返回 false，连接被丢弃）。
    ///
    /// 拆成纯函数是可测性缝：`Err` 分支在 Linux 上不可从真实连接触发
    /// （SO_PEERCRED 对已连接 socket 恒成功），单测直接喂 `io::Error`；
    /// mismatch 分支由 `unix_listener_drops_connections_whose_uid_is_not_the_owner`
    /// 端到端覆盖。
    pub(super) fn peer_gate(
        cred: std::io::Result<tokio::net::unix::UCred>,
        owner_uid: u32,
    ) -> bool {
        match cred {
            Ok(cred) if peer_allowed(cred.uid(), owner_uid) => true,
            Ok(cred) => {
                tracing::warn!(
                    peer_uid = cred.uid(),
                    owner_uid,
                    peer_pid = ?cred.pid(),
                    "dropped unix socket connection: peer uid is not the socket owner"
                );
                false
            }
            Err(err) => {
                // 取不到凭据按拒绝处理（fail-closed）。0600 文件权限
                // 已是内核层主防线，此为兜底层。
                tracing::warn!("dropped unix socket connection: peer cred unavailable: {err}");
                false
            }
        }
    }
}

#[cfg(unix)]
#[cfg(unix)]
impl<L> axum::serve::Listener for UidCheckedListener<L>
where
    L: Accept,
{
    type Io = tokio::net::UnixStream;
    type Addr = tokio::net::unix::SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            match self.inner.accept().await {
                Ok((stream, addr)) => {
                    if Self::peer_gate(stream.peer_cred(), self.owner_uid) {
                        return (stream, addr);
                    }
                    // stream 丢弃 → 对端读到 EOF/RST；继续 accept 下一个
                }
                Err(err) => {
                    // accept 错误语义与 axum serve/listener.rs 一致（连接类
                    // 错误立即重试；其余 log + 1s 退避，防 EMFILE 类打转）。
                    let connection_error = matches!(
                        err.kind(),
                        std::io::ErrorKind::ConnectionRefused
                            | std::io::ErrorKind::ConnectionAborted
                            | std::io::ErrorKind::ConnectionReset
                    );
                    if connection_error {
                        continue;
                    }
                    tracing::error!("accept error: {err}");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        self.inner.local_addr()
    }
}
