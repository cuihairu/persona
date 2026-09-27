//! `persona backup …`：整库加密备份的推送/列举/拉取/恢复/删除。
//!
//! 与事件上报共用 `PERSONA_SERVER_URL` + `PERSONA_SERVER_TOKEN`（env-only、
//! 都非空才启用，敏感值不落盘）。备份体 = VACUUM INTO 快照 → gzip →
//! PERSENC1（`persona_core::backup`），服务器只见密文。
//!
//! push 不要求解锁主密码（物理快照是文件级操作）；restore 换库前先
//! 留 `.bak`。附件 blob 不在 v1 备份内（恢复后元数据在、文件体缺失）。

use anyhow::{bail, Context, Result};
use clap::{Args, Subcommand};
use colored::Colorize;

use crate::config::CliConfig;
use crate::utils::prompt::{PromptUi, TerminalUi};
use persona_core::backup::{create_backup_bytes, restore_backup_bytes, BackupClient};
use persona_core::Database;
use std::path::PathBuf;

#[derive(Args)]
pub struct BackupArgs {
    #[command(subcommand)]
    command: BackupCommand,
}

#[derive(Subcommand)]
enum BackupCommand {
    /// 快照当前库 → 加密 → 推送到服务器（无需解锁主密码）
    Push {
        /// 从指定环境变量读备份口令（CI/自动化；变量必须已设且非空）
        #[arg(long)]
        passphrase_env: Option<String>,
    },
    /// 列出服务器上的备份版本（新→旧）
    List {
        /// 每页条数（服务器默认 20、上限 100）
        #[arg(long, default_value_t = 20)]
        limit: u32,
        /// 上一页返回的游标
        #[arg(long)]
        cursor: Option<String>,
    },
    /// 下载备份密文到文件（不解密、不换库）
    Pull {
        /// 备份版本 id
        id: String,
        /// 输出路径
        #[arg(short, long)]
        out: PathBuf,
    },
    /// 恢复：下载（或 --file 本地密文）→ 解密复验 → 留 .bak → 换库
    Restore {
        /// 要恢复的服务器备份版本 id（与 --file 二选一）
        id: Option<String>,
        /// 本地密文文件（与 id 二选一；离线恢复路径）
        #[arg(long)]
        file: Option<PathBuf>,
        /// 从指定环境变量读备份口令
        #[arg(long)]
        passphrase_env: Option<String>,
        /// 跳过确认提示（危险：直接覆盖当前库）
        #[arg(short, long)]
        yes: bool,
    },
    /// 删除服务器上的备份版本
    Delete {
        /// 备份版本 id
        id: String,
        /// 跳过确认提示
        #[arg(short, long)]
        yes: bool,
    },
}

pub async fn execute(args: BackupArgs, config: &CliConfig) -> Result<()> {
    execute_with(args, config, &TerminalUi).await
}

pub(crate) async fn execute_with(
    args: BackupArgs,
    config: &CliConfig,
    ui: &dyn PromptUi,
) -> Result<()> {
    match args.command {
        BackupCommand::Push { passphrase_env } => {
            // 物理快照无需主密钥；唯一前置是库文件存在
            let db_path = config.get_database_path();
            if !db_path.exists() {
                bail!(
                    "no vault database at {} — run `persona migrate` first",
                    db_path.display()
                );
            }
            let passphrase = resolve_passphrase(passphrase_env.as_deref(), "backup", ui, true)?;
            let client = client_from_env()?;
            let db = Database::from_file(&db_path).await?;
            println!("{}", "📤 Creating encrypted snapshot...".cyan().bold());
            let blob = create_backup_bytes(db.pool(), &passphrase, None).await?;
            let result = client.push(&blob.bytes).await?;
            println!(
                "{}",
                format!(
                    "✅ {} backup {} ({} bytes, sha256 {}…)",
                    if result.deduplicated {
                        "Unchanged"
                    } else {
                        "Pushed"
                    },
                    result.id,
                    result.size_bytes,
                    &result.sha256[..12.min(result.sha256.len())],
                )
                .green()
            );
            println!(
                "   device: {}, created at: {}",
                result.device_name, result.created_at
            );
            Ok(())
        }
        BackupCommand::List { limit, cursor } => {
            let client = client_from_env()?;
            let page = client.list(limit, cursor.as_deref()).await?;
            if page.backups.is_empty() {
                println!("{}", "No backups on the server yet.".yellow());
                return Ok(());
            }
            for backup in &page.backups {
                println!(
                    "  {}  {}  {:>10} bytes  {}  {}",
                    backup.id,
                    backup.device_name,
                    backup.size_bytes,
                    &backup.sha256[..12.min(backup.sha256.len())],
                    backup.created_at
                );
            }
            if let Some(next) = page.next_cursor {
                println!(
                    "{}",
                    format!("-- next page: --cursor {next}").bright_black()
                );
            }
            Ok(())
        }
        BackupCommand::Pull { id, out } => {
            let client = client_from_env()?;
            let downloaded = client.download(&id).await?;
            std::fs::write(&out, &downloaded.bytes)
                .with_context(|| format!("failed to write {}", out.display()))?;
            println!(
                "{}",
                format!(
                    "✅ Pulled {} → {} ({}, sha256 verified)",
                    id,
                    out.display(),
                    downloaded.bytes.len()
                )
                .green()
            );
            Ok(())
        }
        BackupCommand::Restore {
            id,
            file,
            passphrase_env,
            yes,
        } => {
            let (ciphertext, source_label) = match (id, file) {
                (Some(id), None) => {
                    let client = client_from_env()?;
                    println!("{}", "⬇️  Downloading backup...".cyan().bold());
                    (client.download(&id).await?.bytes, format!("server:{id}"))
                }
                (None, Some(path)) => (
                    std::fs::read(&path)
                        .with_context(|| format!("failed to read {}", path.display()))?,
                    path.display().to_string(),
                ),
                (Some(_), Some(_)) => bail!("pass either a backup id or --file, not both"),
                (None, None) => bail!("pass a backup id or --file"),
            };
            let passphrase = {
                // 确认在前、口令在后：用户取消就不该被问口令
                let db_path_probe = config.get_database_path();
                if !yes {
                    let target = if db_path_probe.exists() {
                        format!("replace {} (a .bak copy is kept)", db_path_probe.display())
                    } else {
                        format!("create {}", db_path_probe.display())
                    };
                    if !ui.confirm(
                        &format!("Restore backup from {source_label} and {target}?"),
                        false,
                    )? {
                        println!("{}", "Restore cancelled.".yellow());
                        return Ok(());
                    }
                }
                resolve_passphrase(passphrase_env.as_deref(), "backup", ui, false)?
            };
            let db_path = config.get_database_path();

            // 解密复验到同目录临时文件，成功后才动现有库
            let mut staged = db_path.clone();
            staged.set_extension("restore.tmp");
            restore_backup_bytes(&ciphertext, &passphrase, &staged)
                .context("restore failed; the current vault was not touched")?;
            if db_path.exists() {
                let mut backup_path = db_path.clone();
                backup_path.set_extension("bak");
                std::fs::copy(&db_path, &backup_path)
                    .with_context(|| format!("failed to back up {} first", db_path.display()))?;
            }
            std::fs::rename(&staged, &db_path).with_context(|| {
                format!("failed to move the restored file to {}", db_path.display())
            })?;
            println!(
                "{}",
                format!(
                    "✅ Restored vault from {source_label} → {}",
                    db_path.display()
                )
                .green()
            );
            let backup_path = db_path.with_extension("bak");
            if backup_path.exists() {
                println!(
                    "{}",
                    format!("   previous vault kept at {}", backup_path.display()).bright_black()
                );
            }
            println!(
                "{}",
                "   attachments are NOT part of the backup (metadata only)".yellow()
            );
            Ok(())
        }
        BackupCommand::Delete { id, yes } => {
            if !yes && !ui.confirm(&format!("Delete backup {id} from the server?"), false)? {
                println!("{}", "Delete cancelled.".yellow());
                return Ok(());
            }
            let client = client_from_env()?;
            client.delete(&id).await?;
            println!("{}", format!("🗑️  Deleted backup {id}.").green());
            Ok(())
        }
    }
}

/// `PERSONA_SERVER_URL` + `PERSONA_SERVER_TOKEN` 都非空才构造客户端
/// （fail-closed，与事件上报同一惯例；缺一只直接报错——备份命令没有
/// "静默跳过"的合理降级）。
fn client_from_env() -> Result<BackupClient> {
    let url = non_blank_env("PERSONA_SERVER_URL");
    let token = non_blank_env("PERSONA_SERVER_TOKEN");
    match (url, token) {
        (Some(url), Some(token)) => BackupClient::new(&url, token),
        _ => bail!("PERSONA_SERVER_URL and PERSONA_SERVER_TOKEN must both be set"),
    }
}

fn non_blank_env(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .filter(|value| !value.trim().is_empty())
}

/// 备份口令解析：`--passphrase-env VAR`（必须已设且非空——显式指定
/// 变量名后变量缺失是配置错误，不静默回退）→ `PERSONA_PAYLOAD_PASSPHRASE`
/// → 交互提示。push 带确认（新口令要录两遍），restore 不带（口令是既有的）。
fn resolve_passphrase(
    env_var: Option<&str>,
    kind: &str,
    ui: &dyn PromptUi,
    confirm: bool,
) -> Result<String> {
    if let Some(var) = env_var {
        return std::env::var(var)
            .ok()
            .filter(|value| !value.trim().is_empty())
            .with_context(|| format!("--passphrase-env {var} is not set (or blank)"));
    }
    if let Ok(value) = std::env::var("PERSONA_PAYLOAD_PASSPHRASE") {
        if !value.trim().is_empty() {
            return Ok(value);
        }
    }
    let confirmation = confirm.then_some(("Confirm passphrase", "Passphrases do not match"));
    ui.password(&format!("Enter {kind} passphrase"), false, confirmation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::prompt::scripted::ScriptedUi;
    use persona_core::models::{Identity, IdentityType};
    use persona_core::storage::repository::{IdentityRepository, Repository};
    use std::io::{BufRead, Read, Write};
    use std::sync::{Arc, Mutex};

    /// 进程 env 单槽（PERSONA_* 全局名空间）：与 bridge/switch/ssh/travel
    /// 的 env 测试共用 bridge 测试的全局锁串行。
    fn env_guard() -> std::sync::MutexGuard<'static, ()> {
        crate::commands::bridge::tests::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    fn config_for(dir: &tempfile::TempDir) -> CliConfig {
        let mut config = CliConfig::default();
        config.workspace.path = dir.path().to_path_buf();
        config
    }

    /// 建一个带单个 identity 的库并返回 (库, identity id)。
    async fn seeded_db(path: &std::path::Path) -> Database {
        let db = Database::from_file(path).await.unwrap();
        db.migrate().await.unwrap();
        let repo = IdentityRepository::new(db.clone());
        repo.create(&Identity::new("Seed".to_owned(), IdentityType::Personal))
            .await
            .unwrap();
        db
    }

    async fn identity_count(path: &std::path::Path) -> usize {
        let db = Database::from_file(path).await.unwrap();
        let repo = IdentityRepository::new(db.clone());
        let count = repo.find_all().await.unwrap().len();
        // 显式关闭：drop 只把池交给后台回收，Windows 上句柄可能仍短暂
        // 持有，紧随其后的 restore rename 会撞 os error 5（Access denied）。
        db.close().await;
        count
    }

    #[test]
    fn resolve_passphrase_prefers_explicit_env_var() {
        let _guard = env_guard();
        std::env::set_var("PERSONA_BACKUP_TEST_PW", "from-var");
        // 不预载答案：若实现误走 prompt，ScriptedUi 直接 panic（更强的保护）
        let ui = ScriptedUi::new();
        let got = resolve_passphrase(Some("PERSONA_BACKUP_TEST_PW"), "backup", &ui, true).unwrap();
        assert_eq!(got, "from-var");
        assert!(ui.exhausted(), "explicit var must skip the prompt");

        // 显式指定的变量缺失/空白是配置错误，不静默回退
        std::env::set_var("PERSONA_BACKUP_TEST_PW", "  ");
        let err =
            resolve_passphrase(Some("PERSONA_BACKUP_TEST_PW"), "backup", &ui, true).unwrap_err();
        assert!(err.to_string().contains("--passphrase-env"));
        std::env::remove_var("PERSONA_BACKUP_TEST_PW");
    }

    #[test]
    fn resolve_passphrase_falls_back_to_payload_env_then_prompt() {
        let _guard = env_guard();
        std::env::set_var("PERSONA_PAYLOAD_PASSPHRASE", "payload-pw");
        let ui = ScriptedUi::new();
        let got = resolve_passphrase(None, "backup", &ui, true).unwrap();
        assert_eq!(got, "payload-pw");
        assert!(ui.exhausted());
        std::env::remove_var("PERSONA_PAYLOAD_PASSPHRASE");

        let ui = ScriptedUi::new().password("typed-pw");
        let got = resolve_passphrase(None, "backup", &ui, false).unwrap();
        assert_eq!(got, "typed-pw");
        assert!(ui.exhausted());
    }

    #[test]
    fn client_from_env_fails_closed_without_both_vars() {
        let _guard = env_guard();
        std::env::set_var("PERSONA_SERVER_URL", "http://127.0.0.1:9");
        std::env::remove_var("PERSONA_SERVER_TOKEN");
        let err = match client_from_env() {
            Ok(_) => panic!("client must not be constructed without both env vars"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("must both be set"));
        std::env::remove_var("PERSONA_SERVER_URL");
    }

    #[tokio::test]
    async fn push_requires_existing_vault() {
        let dir = tempfile::tempdir().unwrap();
        let config = config_for(&dir);
        let args = BackupArgs {
            command: BackupCommand::Push {
                passphrase_env: Some("PERSONA_BACKUP_TEST_PW".to_string()),
            },
        };
        std::env::set_var("PERSONA_BACKUP_TEST_PW", "pw");
        let err = execute_with(args, &config, &ScriptedUi::new())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("persona migrate"));
        std::env::remove_var("PERSONA_BACKUP_TEST_PW");
    }

    #[tokio::test]
    async fn restore_from_file_swaps_vault_and_keeps_bak() {
        let dir = tempfile::tempdir().unwrap();
        let config = config_for(&dir);
        let db_path = config.get_database_path();

        // 库 v1（1 个 identity）→ 备份；随后库继续长到 2 个
        let db = seeded_db(&db_path).await;
        let blob = create_backup_bytes(db.pool(), "backup-pass", None)
            .await
            .unwrap();
        let ciphertext_path = dir.path().join("vault.persenc");
        std::fs::write(&ciphertext_path, &blob.bytes).unwrap();
        let repo = IdentityRepository::new(db.clone());
        repo.create(&Identity::new(
            "After Backup".to_owned(),
            IdentityType::Personal,
        ))
        .await
        .unwrap();
        db.close().await;
        assert_eq!(identity_count(&db_path).await, 2);

        // 恢复：确认 yes + 口令（restore 无确认式双录）
        let ui = ScriptedUi::new().confirm(true).password("backup-pass");
        let args = BackupArgs {
            command: BackupCommand::Restore {
                id: None,
                file: Some(ciphertext_path.clone()),
                passphrase_env: None,
                yes: false,
            },
        };
        execute_with(args, &config, &ui).await.unwrap();
        assert!(ui.exhausted());

        // 库回到备份时刻（1 个），.bak 保留覆盖前的状态（2 个）
        let mut bak = db_path.clone();
        bak.set_extension("bak");
        assert_eq!(identity_count(&db_path).await, 1, "restored vault");
        assert_eq!(identity_count(&bak).await, 2, "pre-restore copy");
        let mut staged = db_path.clone();
        staged.set_extension("restore.tmp");
        assert!(!staged.exists(), "staging file must be renamed away");
    }

    #[tokio::test]
    async fn restore_rejects_wrong_passphrase_and_leaves_vault_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let config = config_for(&dir);
        let db_path = config.get_database_path();
        let db = seeded_db(&db_path).await;
        let blob = create_backup_bytes(db.pool(), "right-pass", None)
            .await
            .unwrap();
        let ciphertext_path = dir.path().join("vault.persenc");
        std::fs::write(&ciphertext_path, &blob.bytes).unwrap();
        db.close().await;

        let ui = ScriptedUi::new().confirm(true).password("wrong-pass");
        let args = BackupArgs {
            command: BackupCommand::Restore {
                id: None,
                file: Some(ciphertext_path),
                passphrase_env: None,
                yes: true,
            },
        };
        let err = execute_with(args, &config, &ui).await.unwrap_err();
        assert!(
            err.to_string().contains("not touched"),
            "unexpected error: {err}"
        );
        assert_eq!(identity_count(&db_path).await, 1, "vault unchanged");
        let mut bak = db_path.clone();
        bak.set_extension("bak");
        assert!(!bak.exists(), "no .bak on failed restore");
    }

    // ------------------------------------------------------------------
    // 服务器侧分支（push/list/pull/restore-from-id/delete）。
    //
    // 这些代码的有趣路径全在「请求长什么样」与「响应怎么被解释、落盘、
    // 换库」上，本地没有可替身的对象，所以起一个 loopback 上的极简
    // HTTP/1.1 桩服务（与 cli/tests/integration_test.rs 的事件上报测试
    // 同一惯例）：每个响应都带 `Connection: close`，reqwest 读完即断，
    // 不等 keep-alive → 逐请求串行、结果确定。
    // ------------------------------------------------------------------

    /// 桩响应：(状态码, 附加响应头, 响应体)。
    type StubReply = (u16, Vec<(&'static str, String)>, Vec<u8>);
    type StubHandler = dyn Fn(&str, &str, &[u8]) -> StubReply + Send + Sync;

    /// 桩服务器收到的一条请求（body 全留：要断言推上去的确实是密文）。
    struct Served {
        method: String,
        path: String,
        auth: Option<String>,
        body: Vec<u8>,
    }

    /// 环境变量 RAII：断言失败 panic 时也会清理，不留残留污染同进程里
    /// 其他读 `PERSONA_*` 的测试。
    struct TempEnv {
        key: &'static str,
    }

    impl TempEnv {
        fn set(key: &'static str, value: &str) -> Self {
            std::env::set_var(key, value);
            Self { key }
        }
    }

    impl Drop for TempEnv {
        fn drop(&mut self) {
            std::env::remove_var(self.key);
        }
    }

    /// 把客户端指向桩（`PERSONA_SERVER_URL` + `PERSONA_SERVER_TOKEN`）。
    fn server_env(addr: std::net::SocketAddr) -> (TempEnv, TempEnv) {
        (
            TempEnv::set("PERSONA_SERVER_URL", &format!("http://{addr}")),
            TempEnv::set("PERSONA_SERVER_TOKEN", "test-token"),
        )
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(bytes))
    }

    fn json_response(status: u16, value: &serde_json::Value) -> StubReply {
        (
            status,
            vec![("Content-Type", "application/json".to_owned())],
            value.to_string().into_bytes(),
        )
    }

    /// 起桩：逐条 accept（测试内按序发请求），回 `handler` 的罐头响应，
    /// 并把每条请求记进返回的共享日志。线程随测试进程结束回收。
    fn spawn_stub(handler: Box<StubHandler>) -> (std::net::SocketAddr, Arc<Mutex<Vec<Served>>>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let log: Arc<Mutex<Vec<Served>>> = Arc::new(Mutex::new(Vec::new()));
        let served_log = Arc::clone(&log);
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let mut reader = std::io::BufReader::new(stream);
                let Ok((method, path, headers, body)) = read_request(&mut reader) else {
                    continue;
                };
                let auth = headers.iter().find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("authorization")
                        .then(|| value.trim().to_owned())
                });
                served_log.lock().unwrap().push(Served {
                    method: method.clone(),
                    path: path.clone(),
                    auth,
                    body: body.clone(),
                });
                let (status, extra, reply) = handler(&method, &path, &body);
                let mut stream = reader.into_inner();
                let _ = stream.write_all(&stub_http(status, &extra, &reply));
                let _ = stream.flush();
            }
        });
        (addr, log)
    }

    fn read_request<R: std::io::Read>(
        reader: &mut std::io::BufReader<R>,
    ) -> std::io::Result<(String, String, Vec<String>, Vec<u8>)> {
        let mut request_line = String::new();
        reader.read_line(&mut request_line)?;
        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or_default().to_owned();
        let path = parts.next().unwrap_or_default().to_owned();
        let mut headers = Vec::new();
        let mut content_length = 0usize;
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line)? == 0 {
                return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
            }
            let line = line.trim_end();
            if line.is_empty() {
                break;
            }
            if let Some((name, value)) = line.split_once(':') {
                if name.eq_ignore_ascii_case("content-length") {
                    content_length = value.trim().parse().unwrap_or(0);
                }
            }
            headers.push(line.to_owned());
        }
        let mut body = vec![0u8; content_length];
        if content_length > 0 {
            reader.read_exact(&mut body)?;
        }
        Ok((method, path, headers, body))
    }

    fn stub_http(status: u16, extra: &[(&'static str, String)], body: &[u8]) -> Vec<u8> {
        let reason = match status {
            200 => "OK",
            201 => "Created",
            404 => "Not Found",
            500 => "Internal Server Error",
            _ => "Response",
        };
        let mut head = format!(
            "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n",
            body.len()
        );
        for (name, value) in extra {
            head.push_str(name);
            head.push_str(": ");
            head.push_str(value);
            head.push_str("\r\n");
        }
        let mut out = head.into_bytes();
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(body);
        out
    }

    async fn vault_ready(dir: &tempfile::TempDir) -> CliConfig {
        let config = config_for(dir);
        let db = seeded_db(&config.get_database_path()).await;
        db.close().await;
        config
    }

    fn push_args() -> BackupArgs {
        BackupArgs {
            command: BackupCommand::Push {
                passphrase_env: Some("PERSONA_BACKUP_TEST_PW".to_owned()),
            },
        }
    }

    fn list_args(limit: u32, cursor: Option<&str>) -> BackupArgs {
        BackupArgs {
            command: BackupCommand::List {
                limit,
                cursor: cursor.map(ToOwned::to_owned),
            },
        }
    }

    fn pull_args(id: &str, out: PathBuf) -> BackupArgs {
        BackupArgs {
            command: BackupCommand::Pull {
                id: id.to_owned(),
                out,
            },
        }
    }

    fn restore_args(id: Option<&str>, file: Option<PathBuf>) -> BackupArgs {
        BackupArgs {
            command: BackupCommand::Restore {
                id: id.map(ToOwned::to_owned),
                file,
                passphrase_env: None,
                yes: false,
            },
        }
    }

    fn delete_args(id: &str, yes: bool) -> BackupArgs {
        BackupArgs {
            command: BackupCommand::Delete {
                id: id.to_owned(),
                yes,
            },
        }
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn push_uploads_a_decryptable_snapshot_and_reports_the_verdict() {
        let _guard = env_guard();
        let dir = tempfile::tempdir().unwrap();
        let config = vault_ready(&dir).await;

        let meta = serde_json::json!({
            "id": "b1",
            "device_name": "tester",
            "size_bytes": 4096,
            "sha256": "a".repeat(64),
            "created_at": "2026-09-27T00:00:00Z",
            "deduplicated": false,
        });
        let (addr, log) = spawn_stub(Box::new(move |method, path, _body| {
            assert_eq!(method, "POST");
            assert_eq!(path, "/api/v1/backups");
            json_response(201, &meta)
        }));
        let (_url, _token) = server_env(addr);
        let _pw = TempEnv::set("PERSONA_BACKUP_TEST_PW", "backup-pass");
        execute_with(push_args(), &config, &ScriptedUi::new())
            .await
            .unwrap();

        let served = log.lock().unwrap();
        assert_eq!(served.len(), 1, "push 只该发一个请求");
        assert_eq!(served[0].auth.as_deref(), Some("Bearer test-token"));
        let pushed = served[0].body.clone();
        drop(served);
        assert!(
            !pushed.starts_with(b"SQLite format 3"),
            "推上去的必须是密文，不是明文快照"
        );
        // 承诺的语义是「服务器上的东西能用同一口令恢复」：真解一次。
        let staged = dir.path().join("verify.db");
        restore_backup_bytes(&pushed, "backup-pass", &staged).unwrap();
        assert_eq!(identity_count(&staged).await, 1);
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn push_reports_unchanged_when_server_deduplicates() {
        let _guard = env_guard();
        let dir = tempfile::tempdir().unwrap();
        let config = vault_ready(&dir).await;

        let meta = serde_json::json!({
            "id": "b0",
            "device_name": "tester",
            "size_bytes": 4096,
            "sha256": "b".repeat(64),
            "created_at": "2026-09-26T00:00:00Z",
            "deduplicated": true,
        });
        let (addr, log) = spawn_stub(Box::new(move |_, _, _| json_response(200, &meta)));
        let (_url, _token) = server_env(addr);
        let _pw = TempEnv::set("PERSONA_BACKUP_TEST_PW", "backup-pass");
        execute_with(push_args(), &config, &ScriptedUi::new())
            .await
            .unwrap();
        assert_eq!(log.lock().unwrap().len(), 1);
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn push_surfaces_the_server_error_message_and_status() {
        let _guard = env_guard();
        let dir = tempfile::tempdir().unwrap();
        let config = vault_ready(&dir).await;

        let (addr, log) = spawn_stub(Box::new(|_, _, _| {
            json_response(
                500,
                &serde_json::json!({"error": {"code": "storage_full", "message": "disk full"}}),
            )
        }));
        let (_url, _token) = server_env(addr);
        let _pw = TempEnv::set("PERSONA_BACKUP_TEST_PW", "backup-pass");
        let text = execute_with(push_args(), &config, &ScriptedUi::new())
            .await
            .unwrap_err()
            .to_string();
        assert!(text.contains("push backup failed"), "unexpected: {text}");
        assert!(
            text.contains("disk full"),
            "服务器的 message 要透出来: {text}"
        );
        assert!(text.contains("500"), "状态码要透出来: {text}");
        assert_eq!(log.lock().unwrap().len(), 1);
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn list_renders_rows_and_passes_limit_cursor_through() {
        let _guard = env_guard();
        let dir = tempfile::tempdir().unwrap();
        let config = config_for(&dir);

        // 三页：有行+有游标 → 空页 → 有行无游标（三次打印三种形态）
        let pages = [
            serde_json::json!({
                "backups": [
                    {"id":"b2","device_name":"laptop","size_bytes":2048,
                     "sha256":"c".repeat(64),"created_at":"2026-09-26T10:00:00Z"},
                    {"id":"b1","device_name":"phone","size_bytes":1024,
                     "sha256":"d".repeat(64),"created_at":"2026-09-25T10:00:00Z"}
                ],
                "next_cursor": "cur-2"
            }),
            serde_json::json!({"backups": [], "next_cursor": null}),
            serde_json::json!({
                "backups": [
                    {"id":"b3","device_name":"laptop","size_bytes":3072,
                     "sha256":"e".repeat(64),"created_at":"2026-09-27T10:00:00Z"}
                ],
                "next_cursor": null
            }),
        ];
        let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let tick = Arc::clone(&counter);
        let (addr, log) = spawn_stub(Box::new(move |method, path, _| {
            assert_eq!(method, "GET");
            assert_eq!(path.split('?').next(), Some("/api/v1/backups"));
            let index = tick.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            // 只有第二次调用带游标，且必须是服务器上一页给的那个值（原样回传）
            if index == 1 {
                assert!(path.contains("cursor=cur-2"), "游标必须回传: {path}");
            } else {
                assert!(
                    !path.contains("cursor="),
                    "不带游标的请求不该有 cursor=: {path}"
                );
            }
            json_response(200, &pages[index.min(2)])
        }));
        let (_url, _token) = server_env(addr);

        execute_with(list_args(20, None), &config, &ScriptedUi::new())
            .await
            .unwrap();
        execute_with(list_args(2, Some("cur-2")), &config, &ScriptedUi::new())
            .await
            .unwrap();
        execute_with(list_args(20, None), &config, &ScriptedUi::new())
            .await
            .unwrap();

        assert_eq!(counter.load(std::sync::atomic::Ordering::SeqCst), 3);
        let served = log.lock().unwrap();
        assert!(served[0].path.contains("limit=20"), "{}", served[0].path);
        assert!(served[1].path.contains("limit=2"), "{}", served[1].path);
        assert!(
            served[1].path.contains("cursor=cur-2"),
            "{:#?}",
            served[1].path
        );
        assert!(!served[0].path.contains("cursor="), "首页不该有游标");
        assert!(served
            .iter()
            .all(|r| r.auth.as_deref() == Some("Bearer test-token")));
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn list_reports_the_empty_page_without_error() {
        let _guard = env_guard();
        let dir = tempfile::tempdir().unwrap();
        let config = config_for(&dir);
        let (addr, _log) = spawn_stub(Box::new(|_, _, _| {
            json_response(
                200,
                &serde_json::json!({"backups": [], "next_cursor": null}),
            )
        }));
        let (_url, _token) = server_env(addr);
        execute_with(list_args(20, None), &config, &ScriptedUi::new())
            .await
            .unwrap();
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn pull_writes_verified_bytes_and_refuses_a_mismatch() {
        let _guard = env_guard();
        let dir = tempfile::tempdir().unwrap();
        let config = config_for(&dir);
        let source = seeded_db(&dir.path().join("source.db")).await;
        let blob = create_backup_bytes(source.pool(), "backup-pass", None)
            .await
            .unwrap();
        let digest = sha256_hex(&blob.bytes);
        source.close().await;

        // ① ETag 与字节一致 → 落盘内容必须与服务器给的完全相同
        let bytes = blob.bytes.clone();
        let etag = format!("\"{digest}\"");
        let first_etag = etag.clone();
        let (addr, _log) = spawn_stub(Box::new(move |method, path, _| {
            assert_eq!(method, "GET");
            assert_eq!(path, "/api/v1/backups/b1");
            (200, vec![("ETag", first_etag.clone())], bytes.clone())
        }));
        let (_url, _token) = server_env(addr);
        let out = dir.path().join("vault.persenc");
        execute_with(pull_args("b1", out.clone()), &config, &ScriptedUi::new())
            .await
            .unwrap();
        assert_eq!(std::fs::read(&out).unwrap(), blob.bytes);

        // ② ETag 对不上 → 完整性校验报错，且绝不留半个文件
        let (addr, _log) = spawn_stub(Box::new(|_, _, _| {
            (
                200,
                vec![("ETag", "\"deadbeef\"".to_owned())],
                b"tampered".to_vec(),
            )
        }));
        let _url2 = TempEnv::set("PERSONA_SERVER_URL", &format!("http://{addr}"));
        let bad = dir.path().join("tampered.persenc");
        let text = execute_with(pull_args("b1", bad.clone()), &config, &ScriptedUi::new())
            .await
            .unwrap_err()
            .to_string();
        assert!(
            text.contains("integrity check failed"),
            "unexpected: {text}"
        );
        assert!(!bad.exists(), "校验失败不该落盘");

        // ③ 校验通过但写文件失败 → 错误必须点名「写」而不是「下载」
        let bytes2 = blob.bytes.clone();
        let etag2 = etag.clone();
        let (addr, _log) = spawn_stub(Box::new(move |_, _, _| {
            (200, vec![("ETag", etag2.clone())], bytes2.clone())
        }));
        let _url3 = TempEnv::set("PERSONA_SERVER_URL", &format!("http://{addr}"));
        let nowhere = dir.path().join("no-such-dir").join("vault.persenc");
        let text = execute_with(pull_args("b1", nowhere), &config, &ScriptedUi::new())
            .await
            .unwrap_err()
            .to_string();
        assert!(text.contains("failed to write"), "unexpected: {text}");
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn pull_without_an_etag_header_is_an_error() {
        let _guard = env_guard();
        let dir = tempfile::tempdir().unwrap();
        let config = config_for(&dir);
        let (addr, _log) = spawn_stub(Box::new(|_, _, _| {
            (
                200,
                vec![("Content-Type", "application/octet-stream".to_owned())],
                b"snapshot".to_vec(),
            )
        }));
        let (_url, _token) = server_env(addr);
        let out = dir.path().join("no-etag.persenc");
        let text = execute_with(pull_args("b1", out.clone()), &config, &ScriptedUi::new())
            .await
            .unwrap_err()
            .to_string();
        assert!(
            text.contains("did not return an ETag"),
            "unexpected: {text}"
        );
        assert!(!out.exists(), "拿不到摘要就不该写文件");
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn restore_from_server_id_downloads_swaps_and_keeps_bak() {
        let _guard = env_guard();
        let dir = tempfile::tempdir().unwrap();
        let config = config_for(&dir);
        let db_path = config.get_database_path();

        // 备份出自只有 1 个 identity 的库；现网库继续长到 2 个
        let source = seeded_db(&dir.path().join("source.db")).await;
        let blob = create_backup_bytes(source.pool(), "backup-pass", None)
            .await
            .unwrap();
        let digest = sha256_hex(&blob.bytes);
        source.close().await;
        let live = seeded_db(&db_path).await;
        let repo = IdentityRepository::new(live.clone());
        repo.create(&Identity::new(
            "After Backup".to_owned(),
            IdentityType::Personal,
        ))
        .await
        .unwrap();
        live.close().await;
        assert_eq!(identity_count(&db_path).await, 2);

        let bytes = blob.bytes.clone();
        let etag = format!("\"{digest}\"");
        let (addr, log) = spawn_stub(Box::new(move |method, path, _| {
            assert_eq!(method, "GET");
            assert_eq!(path, "/api/v1/backups/b9");
            (200, vec![("ETag", etag.clone())], bytes.clone())
        }));
        let (_url, _token) = server_env(addr);

        let ui = ScriptedUi::new().confirm(true).password("backup-pass");
        execute_with(restore_args(Some("b9"), None), &config, &ui)
            .await
            .unwrap();
        assert!(ui.exhausted(), "确认与口令提示都应被消费");
        assert_eq!(log.lock().unwrap().len(), 1, "restore 只下载一次");

        assert_eq!(identity_count(&db_path).await, 1, "库回到备份时刻");
        let bak = db_path.with_extension("bak");
        assert_eq!(identity_count(&bak).await, 2, "覆盖前的状态留在 .bak");
        let staged = db_path.with_extension("restore.tmp");
        assert!(!staged.exists(), "暂存文件必须被 rename 走");
    }

    #[tokio::test]
    async fn restore_requires_exactly_one_source() {
        // 两个来源都给 / 都不给：在碰 env、碰磁盘之前就 bail，故无需
        // env_guard 也无需桩服务器。
        let dir = tempfile::tempdir().unwrap();
        let config = config_for(&dir);

        let both = restore_args(Some("b1"), Some(dir.path().join("x.persenc")));
        let text = execute_with(both, &config, &ScriptedUi::new())
            .await
            .unwrap_err()
            .to_string();
        assert!(text.contains("not both"), "unexpected: {text}");

        let neither = restore_args(None, None);
        let text = execute_with(neither, &config, &ScriptedUi::new())
            .await
            .unwrap_err()
            .to_string();
        assert!(
            text.contains("pass a backup id or --file"),
            "unexpected: {text}"
        );
    }

    #[tokio::test]
    async fn restore_from_a_missing_file_names_the_read_failure() {
        let dir = tempfile::tempdir().unwrap();
        let config = config_for(&dir);
        let missing = dir.path().join("gone.persenc");
        let text = execute_with(
            restore_args(None, Some(missing)),
            &config,
            &ScriptedUi::new(),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(text.contains("failed to read"), "unexpected: {text}");
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn delete_cancels_locally_and_reports_the_server_verdict() {
        let _guard = env_guard();
        let dir = tempfile::tempdir().unwrap();
        let config = config_for(&dir);

        // ① 取消：确认门在构造客户端之前，一个字节都不该出网
        let (addr, log) = spawn_stub(Box::new(|_, _, _| {
            json_response(200, &serde_json::json!({}))
        }));
        let (_url, _token) = server_env(addr);
        let ui = ScriptedUi::new().confirm(false);
        execute_with(delete_args("b1", false), &config, &ui)
            .await
            .unwrap();
        assert!(ui.exhausted());
        assert!(log.lock().unwrap().is_empty(), "取消后不得打到服务器");

        // ② --yes → DELETE 到位、带 Bearer
        execute_with(delete_args("b1", true), &config, &ScriptedUi::new())
            .await
            .unwrap();
        {
            let served = log.lock().unwrap();
            assert_eq!(served.len(), 1);
            assert_eq!(served[0].method, "DELETE");
            assert_eq!(served[0].path, "/api/v1/backups/b1");
            assert_eq!(served[0].auth.as_deref(), Some("Bearer test-token"));
        }

        // ③ 404 视为幂等成功（已删过的版本）
        let (addr, _log) = spawn_stub(Box::new(|_, _, _| {
            json_response(
                404,
                &serde_json::json!({"error": {"code": "not_found", "message": "no such backup"}}),
            )
        }));
        let _url2 = TempEnv::set("PERSONA_SERVER_URL", &format!("http://{addr}"));
        execute_with(delete_args("b1", true), &config, &ScriptedUi::new())
            .await
            .unwrap();

        // ④ 其他状态码 → 报错带服务器的 message
        let (addr, _log) = spawn_stub(Box::new(|_, _, _| {
            json_response(
                500,
                &serde_json::json!({"error": {"code": "db", "message": "readonly"}}),
            )
        }));
        let _url3 = TempEnv::set("PERSONA_SERVER_URL", &format!("http://{addr}"));
        let text = execute_with(delete_args("b1", true), &config, &ScriptedUi::new())
            .await
            .unwrap_err()
            .to_string();
        assert!(text.contains("delete backup failed"), "unexpected: {text}");
        assert!(text.contains("readonly"), "unexpected: {text}");
    }

    #[test]
    fn blank_payload_passphrase_env_still_prompts() {
        let _guard = env_guard();
        // 已设但全空白：视同没设，必须走交互（否则拿空串当口令）
        let _payload = TempEnv::set("PERSONA_PAYLOAD_PASSPHRASE", "   ");
        let ui = ScriptedUi::new().password("typed-after-blank");
        let got = resolve_passphrase(None, "backup", &ui, false).unwrap();
        assert_eq!(got, "typed-after-blank");
        assert!(ui.exhausted());
    }

    #[test]
    fn client_from_env_rejects_blank_values_and_accepts_a_complete_pair() {
        let _guard = env_guard();
        let _blank = TempEnv::set("PERSONA_SERVER_URL", "  ");
        let _token = TempEnv::set("PERSONA_SERVER_TOKEN", "tok");
        assert!(
            client_from_env().is_err(),
            "空白 URL 视同缺失（fail-closed）"
        );
        let _url = TempEnv::set("PERSONA_SERVER_URL", "http://127.0.0.1:9/");
        assert!(client_from_env().is_ok(), "两个都非空才构造客户端");
    }

    #[tokio::test]
    async fn restore_requires_confirmation_when_not_forced() {
        let dir = tempfile::tempdir().unwrap();
        let config = config_for(&dir);
        let db_path = config.get_database_path();
        let db = seeded_db(&db_path).await;
        let blob = create_backup_bytes(db.pool(), "backup-pass", None)
            .await
            .unwrap();
        let ciphertext_path = dir.path().join("vault.persenc");
        std::fs::write(&ciphertext_path, &blob.bytes).unwrap();
        db.close().await;

        // confirm(false) → 取消；口令提示不应到达（确认在前）
        let ui = ScriptedUi::new().confirm(false);
        let args = BackupArgs {
            command: BackupCommand::Restore {
                id: None,
                file: Some(ciphertext_path),
                passphrase_env: None,
                yes: false,
            },
        };
        execute_with(args, &config, &ui).await.unwrap();
        assert!(ui.exhausted());
        assert_eq!(
            identity_count(&db_path).await,
            1,
            "cancelled restore is a no-op"
        );
        let mut bak = db_path.clone();
        bak.set_extension("bak");
        assert!(!bak.exists());
    }
}
