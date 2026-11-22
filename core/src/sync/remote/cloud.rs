//! 云盘传输（Phase 2）：`CloudDriveRemote` 把 [`SyncRemote`] 实现到本机
//! 云盘同步目录（iCloud Drive / Dropbox / Google Drive 的本地同步文件夹，
//! OS 云代理负责跨设备分发），`CloudGroupKeyStore` 把 [`GroupKeyStore`]
//! 实现到同一目录（设备登记表 + 每设备一枚组密钥信封文件）。
//!
//! **传输红线**（`docs/STORAGE_AND_SYNC.md` §云盘）：云盘目录只放**加密
//! 产物**——绝不放活 `identities.db`（SQLite WAL 伴生文件会被云盘双向同步
//! 打坏）。本模块只写指令分片（oplog 密文行）、快照（group key 整包密文）
//! 与信封（X25519 密封），全是密文；主库快照由宿主的 `VACUUM INTO` 自洽
//! 单文件产出（备份链同源）。
//!
//! **与 HTTP 传输的语义差异（诚实登记）**：
//! - **oplog 分片永远不物理裁剪**。服务器在快照上传后同事务删 `seq ≤ S`
//!   的 ops（压缩），云盘没有这个压缩机制——分片是 append-only，快照是
//!   逻辑检查点（新设备装快照后仍可全量重放，数据不因裁剪而丢）。
//!   `put_library_snapshot` 恒返回 0（本实现不物理压缩）。
//! - **游标是每分片行数水位**（`{"<device>": 行数, …}`），不是全局 rank。
//!   rank 游标会跳过「晚到但 lamport 更小」的 op（设备 B 离线补写低
//!   lamport 的 op 插到已消费的 rank 之前）——行数水位读全分片增量再
//!   按 `(lamport, device_id, op_id)` 合并，永不跳过。
//! - **pull 忽略 limit**：云盘是本地文件读，返回全部分片增量（一次一个
//!   页面）；引擎按「空页才停」循环语义天然收敛。
//!
//! **游标复用 canonical 格式**：水位编码进 `v1:{sum}:{map}` 的 `op_id`
//! 槽（`sum` = 已消费行数，`map` = 每分片行数 JSON）。`local_watermark`
//! 只读 `sum`（已消费行数 = 去重后 op 计数，因 op_id 全局唯一跨分片），
//! `SNAPSHOT_RESUME_OP_ID="0"`（引擎快照装包后写入的游标）解成空 map =
//! 全量读——`sum` 槽保持语义，`decode_cursor` 只校验 `op_id` 非空，槽内
//! JSON 不被任何既有消费者解读（已核验：engine/测试只取 `.0`）。

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use uuid::Uuid;

use super::admin::SyncGroupKeyEntry;
use super::group_key_store::GroupKeyStore;
use crate::sync::device::DeviceIdentity;
use crate::sync::engine::SyncRemote;
use crate::sync::oplog::SyncOp;
use crate::{PersonaError, Result};

/// 云盘分片文件名前缀/后缀（`dev-<device_id>.jsonl`）。
const SHARD_PREFIX: &str = "dev-";
const SHARD_SUFFIX: &str = ".jsonl";
/// 快照文件名前缀/后缀（`snapshot-<seq>-<device_id>.bin`）。
const SNAPSHOT_PREFIX: &str = "snapshot-";
const SNAPSHOT_SUFFIX: &str = ".bin";
/// 信封文件名（`env-<device_id>.bin`）。
const ENV_PREFIX: &str = "env-";
const ENV_SUFFIX: &str = ".bin";
/// 设备登记表文件名。
const REGISTRY_FILE: &str = "registry.json";

/// 云盘目录上的 [`SyncRemote`]。`device_id` 是本设备（决定 push 写哪个
/// 分片）。所有文件操作都是本地原子写（temp + fsync + rename），保证云盘
/// 同步代理永远看不到半行分片。
pub struct CloudDriveRemote {
    dir: PathBuf,
    device_id: Uuid,
}

impl CloudDriveRemote {
    pub fn new(dir: impl Into<PathBuf>, device_id: Uuid) -> Self {
        Self {
            dir: dir.into(),
            device_id,
        }
    }
}

/// 云盘目录上的 [`GroupKeyStore`]：`registry.json`（设备登记表）+
/// `env-<device_id>.bin`（每设备一枚组密钥信封）+ `env-<device_id>.meta.json`
/// （sealed_by/created_at 元数据）。
pub struct CloudGroupKeyStore {
    dir: PathBuf,
}

impl CloudGroupKeyStore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }
}

// ---------------------------------------------------------------------------
// 设备登记表 + 信封（GroupKeyStore）
// ---------------------------------------------------------------------------

#[derive(Debug, serde::Serialize, serde::Deserialize, Default)]
struct CloudRegistry {
    #[serde(default)]
    devices: Vec<CloudDevice>,
}

/// 云盘设备登记表的单条记录（宿主设备列表/授权目标公钥取用）。
///
/// `public_key` 是 base64 的 X25519 公钥——授权设备用它重封组密钥信封
/// （与服务器侧 [`crate::sync::remote::SyncDevice::public_key`] 同义）。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CloudDevice {
    pub device_id: String,
    pub device_name: String,
    pub public_key: String,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub remark: String,
}

async fn read_registry(dir: &Path) -> Result<CloudRegistry> {
    let path = dir.join(REGISTRY_FILE);
    let text = match tokio::fs::read_to_string(&path).await {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(CloudRegistry::default()),
        Err(e) => return Err(PersonaError::Io(format!("read sync registry failed: {e}")).into()),
    };
    let registry: CloudRegistry = serde_json::from_str(&text)
        .map_err(|e| PersonaError::Io(format!("malformed sync registry {REGISTRY_FILE}: {e}")))?;
    Ok(registry)
}

async fn write_registry(dir: &Path, registry: &CloudRegistry) -> Result<()> {
    let text = serde_json::to_vec_pretty(registry)
        .map_err(|e| PersonaError::Io(format!("encode sync registry failed: {e}")))?;
    atomic_write(dir, REGISTRY_FILE, &text).await
}

/// 原子写：同目录 temp + fsync + rename（云盘代理只看到完整文件）。
async fn atomic_write(dir: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    tokio::fs::create_dir_all(dir)
        .await
        .map_err(|e| PersonaError::Io(format!("create cloud drive dir failed: {e}")))?;
    let tmp = dir.join(format!(".{name}.tmp-{}", Uuid::new_v4()));
    tokio::fs::write(&tmp, bytes)
        .await
        .map_err(|e| PersonaError::Io(format!("write temp file failed: {e}")))?;
    if let Ok(f) = tokio::fs::File::open(&tmp).await {
        let _ = f.sync_all().await;
    }
    tokio::fs::rename(&tmp, dir.join(name))
        .await
        .map_err(|e| PersonaError::Io(format!("rename temp file failed: {e}")))?;
    Ok(())
}

/// 从 meta JSON 读字符串字段（缺失/坏 meta 回默认）。
async fn meta_string(dir: &Path, device_id: Uuid, field: &str, default: String) -> String {
    let path = dir.join(format!("{ENV_PREFIX}{device_id}.meta.json"));
    match tokio::fs::read_to_string(&path).await {
        Ok(text) => serde_json::from_str::<serde_json::Value>(&text)
            .ok()
            .and_then(|v| v.get(field).and_then(|x| x.as_str()).map(String::from))
            .unwrap_or(default),
        Err(_) => default,
    }
}

#[async_trait]
impl GroupKeyStore for CloudGroupKeyStore {
    async fn register_device(&self, identity: &DeviceIdentity) -> Result<()> {
        let mut registry = read_registry(&self.dir).await?;
        if registry
            .devices
            .iter()
            .any(|d| d.device_id == identity.device_id.to_string())
        {
            return Ok(()); // 幂等：重复登记同设备无副作用
        }
        if registry
            .devices
            .iter()
            .any(|d| d.device_name == identity.device_name)
        {
            return Err(PersonaError::InvalidInput(format!(
                "device name '{}' already registered in cloud sync group",
                identity.device_name
            ))
            .into());
        }
        registry.devices.push(CloudDevice {
            device_id: identity.device_id.to_string(),
            device_name: identity.device_name.clone(),
            public_key: B64.encode(identity.key_pair.public_bytes()),
            created_at: chrono::Utc::now().to_rfc3339(),
            remark: String::new(),
        });
        write_registry(&self.dir, &registry).await
    }

    async fn put_group_key(&self, device_id: Uuid, envelope: &[u8]) -> Result<()> {
        let registry = read_registry(&self.dir).await?;
        if !registry
            .devices
            .iter()
            .any(|d| d.device_id == device_id.to_string())
        {
            return Err(PersonaError::NotFound(
                "device not registered in cloud sync group".to_string(),
            )
            .into());
        }
        atomic_write(
            &self.dir,
            &format!("{ENV_PREFIX}{device_id}{ENV_SUFFIX}"),
            envelope,
        )
        .await?;
        let meta = serde_json::json!({
            "sealed_by": "",
            "created_at": chrono::Utc::now().to_rfc3339(),
        });
        atomic_write(
            &self.dir,
            &format!("{ENV_PREFIX}{device_id}.meta.json"),
            meta.to_string().as_bytes(),
        )
        .await
    }

    async fn group_keys(&self) -> Result<Vec<SyncGroupKeyEntry>> {
        let registry = read_registry(&self.dir).await?;
        let mut keys = Vec::new();
        for device in &registry.devices {
            let device_id = Uuid::parse_str(&device.device_id).map_err(|_| {
                PersonaError::Io("malformed device_id in sync registry".to_string())
            })?;
            let env_path = self
                .dir
                .join(format!("{ENV_PREFIX}{device_id}{ENV_SUFFIX}"));
            // 无信封 = 待授权（已登记但信封未上传）→ 跳过，与服务器同语义。
            let Ok(envelope) = tokio::fs::read(&env_path).await else {
                continue;
            };
            keys.push(SyncGroupKeyEntry {
                device_id,
                envelope,
                sealed_by: meta_string(&self.dir, device_id, "sealed_by", String::new()).await,
                created_at: meta_string(
                    &self.dir,
                    device_id,
                    "created_at",
                    device.created_at.clone(),
                )
                .await,
            });
        }
        Ok(keys)
    }

    async fn bootstrap_group_if_empty(
        &self,
        device_id: Uuid,
        device_public: &[u8; 32],
    ) -> Result<bool> {
        if !self.group_keys().await?.is_empty() {
            return Ok(false);
        }
        let group = crate::sync::keys::GroupKey::generate()?;
        let envelope = crate::sync::envelope::seal_group_key(group.as_bytes(), device_public)?;
        self.put_group_key(device_id, &envelope).await?;
        Ok(true)
    }
}

impl CloudGroupKeyStore {
    /// 列出云盘登记表的全部设备（含公钥，授权时取目标公钥用）。
    /// 登记表不存在 = 空组。
    pub async fn list_devices(&self) -> Result<Vec<CloudDevice>> {
        Ok(read_registry(&self.dir).await?.devices)
    }

    /// 从登记表移除设备（吊销/离开）。尽力删除该设备的信封与 meta 文件
    /// （残留文件不影响正确性：`group_keys` 以登记表为准，已移除设备不再
    /// 读）。返回是否真的在登记表里删掉了（false = 不在表内，幂等）。
    pub async fn remove_device(&self, device_id: Uuid) -> Result<bool> {
        let mut registry = read_registry(&self.dir).await?;
        let before = registry.devices.len();
        registry
            .devices
            .retain(|d| d.device_id != device_id.to_string());
        if registry.devices.len() == before {
            return Ok(false);
        }
        write_registry(&self.dir, &registry).await?;
        // 信封/meta 删除尽力而为：文件系统错误只 warn（登记表已不含该
        // 设备，孤儿文件由后续 GC 或用户清理兜底）。
        for name in [
            format!("{ENV_PREFIX}{device_id}{ENV_SUFFIX}"),
            format!("{ENV_PREFIX}{device_id}.meta.json"),
        ] {
            if let Err(e) = tokio::fs::remove_file(self.dir.join(&name)).await {
                if e.kind() != std::io::ErrorKind::NotFound {
                    tracing::warn!(error = %e, file = %name, "remove cloud envelope file failed");
                }
            }
        }
        Ok(true)
    }

    /// 写设备备注（登记表内的自由文本；命令层自行保证只写本机设备）。
    /// 返回规整（trim）后的备注。设备不在登记表 → NotFound（fail-closed）。
    pub async fn set_device_remark(&self, device_id: Uuid, remark: &str) -> Result<String> {
        let mut registry = read_registry(&self.dir).await?;
        let stored = remark.trim().to_string();
        let mut found = false;
        for device in &mut registry.devices {
            if device.device_id == device_id.to_string() {
                device.remark = stored.clone();
                found = true;
                break;
            }
        }
        if !found {
            return Err(PersonaError::NotFound(format!(
                "device {device_id} not in cloud sync registry"
            ))
            .into());
        }
        write_registry(&self.dir, &registry).await?;
        Ok(stored)
    }
}

// ---------------------------------------------------------------------------
// 指令流 + 快照（SyncRemote）
// ---------------------------------------------------------------------------

/// 列目录下的全部分片（`dev-*.jsonl`），解析出 device_id。
async fn list_shards(dir: &Path) -> Result<Vec<(Uuid, PathBuf)>> {
    let mut out = Vec::new();
    let mut entries = tokio::fs::read_dir(dir)
        .await
        .map_err(|e| PersonaError::Io(format!("read cloud drive dir failed: {e}")))?;
    while let Some(entry) = entries
        .next_entry()
        .await
        .map_err(|e| PersonaError::Io(format!("read cloud drive dir entry failed: {e}")))?
    {
        let name = entry.file_name().to_string_lossy().to_string();
        let Some(rest) = name
            .strip_prefix(SHARD_PREFIX)
            .and_then(|r| r.strip_suffix(SHARD_SUFFIX))
        else {
            continue;
        };
        let Ok(device_id) = Uuid::parse_str(rest) else {
            continue; // 非本协议的 dev- 文件（如用户手放）→ 跳过
        };
        out.push((device_id, entry.path()));
    }
    out.sort_by_key(|(id, _)| *id);
    Ok(out)
}

/// 读一个分片的全部 op 行。坏行跳过（与 HTTP pull 的单条容错口径一致：
/// 一条损坏不废整批、不卡游标——游标按行数推进，坏行也算已消费）。
async fn read_shard_ops(path: &Path) -> Result<Vec<SyncOp>> {
    let text = match tokio::fs::read_to_string(path).await {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => {
            return Err(PersonaError::Io(format!("read shard failed: {e}")).into());
        }
    };
    let mut ops = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match serde_json::from_str::<SyncOp>(line) {
            Ok(op) => ops.push(op),
            Err(e) => {
                tracing::warn!(error = %e, "malformed op line in cloud shard; skipped");
            }
        }
    }
    Ok(ops)
}

/// 列目录下的快照（`snapshot-*.bin`），解析 `(seq, device_id)`，按 seq 升序。
async fn list_snapshots(dir: &Path) -> Result<Vec<(i64, Uuid, PathBuf)>> {
    let mut out = Vec::new();
    let mut entries = match tokio::fs::read_dir(dir).await {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => {
            return Err(PersonaError::Io(format!("read cloud drive dir failed: {e}")).into());
        }
    };
    while let Some(entry) = entries
        .next_entry()
        .await
        .map_err(|e| PersonaError::Io(format!("read cloud drive dir entry failed: {e}")))?
    {
        let name = entry.file_name().to_string_lossy().to_string();
        let Some(rest) = name
            .strip_prefix(SNAPSHOT_PREFIX)
            .and_then(|r| r.strip_suffix(SNAPSHOT_SUFFIX))
        else {
            continue;
        };
        // `snapshot-<seq>-<device_id>.bin` → rest = `<seq>-<device_id>`
        let Some((seq_str, dev_str)) = rest.split_once('-') else {
            continue;
        };
        let Ok(seq) = seq_str.parse::<i64>() else {
            continue;
        };
        let Ok(device_id) = Uuid::parse_str(dev_str) else {
            continue;
        };
        out.push((seq, device_id, entry.path()));
    }
    out.sort_by_key(|(seq, _, _)| *seq);
    Ok(out)
}

/// 游标的每分片行数水位表（op_id 槽里的 JSON `{"<device>": 行数}`）。
type Watermarks = HashMap<Uuid, u64>;

/// 从游标 op_id 槽解水位表。槽为 `"0"`（快照装包哨兵）或不可解析 →
/// 空表 = 全量读（安全侧：永不跳过，宁可重读让引擎按 op_id 去重）。
fn decode_watermarks(op_id_slot: &str) -> Watermarks {
    if op_id_slot == "0" {
        return Watermarks::new();
    }
    let Ok(value) = serde_json::from_str::<serde_json::Value>(op_id_slot) else {
        return Watermarks::new();
    };
    let Some(map) = value.as_object() else {
        return Watermarks::new();
    };
    let mut out = Watermarks::new();
    for (key, v) in map {
        if let (Ok(id), Some(count)) = (Uuid::parse_str(key), v.as_u64()) {
            out.insert(id, count);
        }
    }
    out
}

fn encode_watermarks(watermarks: &Watermarks) -> String {
    let mut sorted: Vec<_> = watermarks.iter().collect();
    sorted.sort_by_key(|(id, _)| **id);
    let map: serde_json::Map<String, serde_json::Value> = sorted
        .iter()
        .map(|(id, count)| (id.to_string(), serde_json::Value::from(**count)))
        .collect();
    serde_json::Value::Object(map).to_string()
}

/// 合并排序键：`(lamport, device_id, op_id)`——与 oplog LWW 全序同构
/// （op_id 破平保证确定性；跨分片 op_id 全局唯一，平局几乎不发生）。
fn merge_sort_key(op: &SyncOp) -> (u64, Uuid, Uuid) {
    (op.lamport, op.device_id, op.op_id)
}

#[async_trait]
impl SyncRemote for CloudDriveRemote {
    async fn push_ops(&self, ops: &[SyncOp]) -> Result<(u64, u64)> {
        let path = self
            .dir
            .join(format!("{SHARD_PREFIX}{}{SHARD_SUFFIX}", self.device_id));
        // 读现有分片去重（op_id 幂等：崩溃后重推同 op 不再追加）。
        let existing = read_shard_ops(&path).await?;
        let mut known: HashMap<Uuid, ()> = existing.iter().map(|op| (op.op_id, ())).collect();
        let mut lines: Vec<String> = Vec::new();
        let mut accepted = 0u64;
        let mut duplicates = 0u64;
        for op in ops {
            if known.contains_key(&op.op_id) {
                duplicates += 1;
                continue;
            }
            known.insert(op.op_id, ());
            lines.push(
                serde_json::to_string(op)
                    .map_err(|e| PersonaError::Io(format!("encode op line failed: {e}")))?,
            );
            accepted += 1;
        }
        if !lines.is_empty() {
            // 追加语义：读原文本（保留坏行原样），拼上新行，原子 rename。
            // 云盘代理永远看不到半行分片。
            let raw = tokio::fs::read_to_string(&path).await.unwrap_or_default();
            let mut final_buf = raw.into_bytes();
            for line in &lines {
                final_buf.extend_from_slice(line.as_bytes());
                final_buf.push(b'\n');
            }
            atomic_write(
                &self.dir,
                &format!("{SHARD_PREFIX}{}{SHARD_SUFFIX}", self.device_id),
                &final_buf,
            )
            .await?;
        }
        Ok((accepted, duplicates))
    }

    async fn pull_ops(
        &self,
        since: Option<&str>,
        _limit: u32,
    ) -> Result<(Vec<SyncOp>, Option<String>)> {
        // 水位表：None / "0" / 坏槽 → 全量读（安全侧）。
        let watermarks = match since {
            Some(raw) => crate::sync::cursor::decode_cursor(raw)
                .map(|(_, slot)| decode_watermarks(&slot))
                .unwrap_or_default(),
            None => Watermarks::new(),
        };
        let shards = list_shards(&self.dir).await?;
        let mut new_ops: Vec<SyncOp> = Vec::new();
        let mut next = watermarks.clone();
        for (device_id, path) in &shards {
            let ops = read_shard_ops(path).await?;
            let start = watermarks.get(device_id).copied().unwrap_or(0) as usize;
            if start < ops.len() {
                new_ops.extend(ops[start..].iter().cloned());
                next.insert(*device_id, ops.len() as u64);
            }
        }
        if new_ops.is_empty() {
            return Ok((Vec::new(), None));
        }
        // 确定性合并 + op_id 去重（重读安全网：同 op 跨页/重放只留一份）。
        new_ops.sort_by_key(merge_sort_key);
        let mut seen = std::collections::HashSet::new();
        new_ops.retain(|op| seen.insert(op.op_id));
        let total: u64 = next.values().sum();
        let cursor = crate::sync::cursor::encode_cursor(total as i64, &encode_watermarks(&next));
        Ok((new_ops, Some(cursor)))
    }

    async fn head_seq(&self) -> Result<i64> {
        // 组最新版本号 = 全部分片行数总和（op_id 跨分片全局唯一 → 行数
        // 即去重 op 计数）。
        let shards = list_shards(&self.dir).await?;
        let mut total = 0i64;
        for (_, path) in &shards {
            total += read_shard_ops(path).await?.len() as i64;
        }
        Ok(total)
    }

    async fn put_library_snapshot(
        &self,
        seq: i64,
        device_id: &str,
        ciphertext: &[u8],
    ) -> Result<u64> {
        // 文件名内容寻址 `(seq, device_id)`：不同设备永不写同一文件，
        // 同 (seq, device) 重传幂等（跳过，不可变——快照文件一旦写入不改）。
        // 恒返回 0：云盘分片不物理裁剪（见模块文档语义差异）。
        let name = format!("{SNAPSHOT_PREFIX}{seq}-{device_id}{SNAPSHOT_SUFFIX}");
        if self.dir.join(&name).exists() {
            return Ok(0);
        }
        atomic_write(&self.dir, &name, ciphertext).await?;
        Ok(0)
    }

    async fn get_library_snapshot(&self) -> Result<Option<(i64, Vec<u8>)>> {
        // 取最大 seq 的快照（并发多设备各写一份 → max-seq 是确定收敛点）。
        let snapshots = list_snapshots(&self.dir).await?;
        let Some((seq, _device_id, path)) = snapshots.last() else {
            return Ok(None);
        };
        let bytes = tokio::fs::read(path)
            .await
            .map_err(|e| PersonaError::Io(format!("read snapshot file failed: {e}")))?;
        Ok(Some((*seq, bytes)))
    }
}
