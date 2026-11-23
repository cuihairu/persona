# 云盘同步传输（阶段二）

> 状态：**已设计、核心已落地**（2026-11-23）。这是与 server 传输一起设计
> 的两种同步传输之一（用户令：「基于类似 iCloud 这种云盘的同步方式还有
> 通过 server 的方式都一起设计」）。**server 传输是默认**；云盘传输是
> 「不想自建/信任服务器、但每台设备都有云盘目录（iCloud Drive /
> Dropbox / Google Drive）」时的选择。

**协议不变**：同一套指令流（oplog）引擎、Lamport 时钟、LWW 冲突裁决、
组密钥 E2EE、travel 闸全部照用。云盘同步只换**传输**——加密指令流与组
密钥信封放在哪。本文只讲传输，不讲协议（协议见
[`E2EE_SYNC_DESIGN.zh.md`](./E2EE_SYNC_DESIGN.zh.md) 与
[`sync-group-mode.zh.md`](./sync-group-mode.zh.md)）。

## 1. 为什么云盘目录可以当中转

云盘目录（iCloud Drive、Dropbox、Google Drive…）是一个**尽力而为、最终
一致**的共享文件系统：挂载同一目录的每台设备看到同样文件，OS 云代理在
设备间分发变更，不需要我们自建任何服务器。

只要往这个目录里**只写密文**，云供应商看到的就只是不透明字节——与自建
中转完全相同的「零知识」性质，而且零基础设施。代价是：目录是**可用性**
的信任边界（目录不可达 = 无法同步），云供应商原则上可以删除/回滚文件
（威胁模型已如实登记——与跨设备同步的「不信任服务器」立场一致）。

> ⚠️ **红线**（沿 `STORAGE_AND_SYNC.zh.md` §「网盘目录」）：**绝不要把
> 活跃的 `identities.db` 放进云盘同步目录**。SQLite 假定独占写；云盘双向
> 同步会产生冲突副本与真实的损坏风险。本传输只写每设备指令分片、快照
> 与信封——全是密文，没有 SQLite。

## 2. 目录布局

```
<cloud_drive_dir>/
├── dev-<device_id>.jsonl           # 每设备 append-only 指令分片
├── snapshot-<seq>-<device_id>.bin  # 不可变整库快照（密文）
├── env-<device_id>.bin             # 组密钥信封（X25519 密封）
├── env-<device_id>.meta.json       # {sealed_by, created_at} 展示元数据
└── registry.json                   # 设备登记表 {device_id, name, pubkey}
```

- **`dev-<device_id>.jsonl`**：每行一个 JSON `SyncOp`，只有该设备会追加。
  append-only；永不物理裁剪（见 §4）。
- **`snapshot-<seq>-<device_id>.bin`**：组密钥加密的整库快照（与 server
  传输的快照同载荷）。按 `(seq, device_id)` 内容寻址，并发设备永不写同
  一文件，不需要 CAS/409 门控。
- **`env-<device_id>.bin`**：该设备的组密钥信封，密封到其 X25519 公钥
  （与 server 传输同一 `seal_group_key`）。组密钥本身永不出现在目录里。
- **`registry.json`**：设备名册（谁入过组），新设备不需要服务器就能发现
  组与成员。

所有写入都是**原子的**（同目录 temp + fsync + rename），同步中的云代理
永远看不到写了一半的行或文件。

## 3. 指令流传输（`CloudDriveRemote`）

实现与 server 传输相同的 `SyncRemote` trait（`core/src/sync/engine.rs`），
引擎、oplog、LWW、物化层、快照原语、GC 全部原样复用。

### 3.1 没有服务器 seq 的全序

服务器分配单调 `seq`（SQLite AUTOINCREMENT）。云盘目录没有这样的计数器，
传输层从数据**合成**全序：

- 每条 op 是 `(lamport, device_id, op_id)`；op_id **跨分片全局唯一**
  （每条 op 恰好由一台设备创建、恰好追加进一个分片）。
- 虚拟全序 = **按 `(lamport, device_id)` 排序**（op_id 破罕见平局），
  恰好就是协议的 LWW 序。任何设备读同一分片集都算出同一顺序——确定性
  收敛。
- `head_seq` = **全部分片行数总和**（op_id 全局唯一 → 行数即去重 op 计数，
  与服务器 `max(oplog.seq, snapshot.seq)` 报告的是同一个量）。

### 3.2 续拉游标：每分片行数水位

服务器游标是 `v1:{seq}:{op_id}`（rank）。rank 游标在目录场景有一个真实
的洞：设备 B 离线后补写一条 **lamport 更小** 的 op（B 在自己分片更晚的
op 之后才写 lamport 3），该 op 在全序里排在 B 已消费的 rank **之前**，
rank 游标会永久跳过它。

因此云盘传输把**每分片行数水位**编进游标，复用 canonical `v1:` 格式：

```
cursor = encode_cursor(水位总和, "<device -> 已消费行数的 JSON map>")
```

- `seq` 槽存各分片已消费行数之和（「高水位」）——`local_watermark()`、
  `behind`、`library_snapshot_needed` 语义**零改动**（它们只读 `seq` 槽）。
- `op_id` 槽存 JSON map `{"<device_id>": 行数}`。该槽对所有既有消费者都是
  不透明的（只校验非空），复用是安全的。
- `pull_ops` 读**每个**分片的全部未消费行，按 `(lamport, device_id,
op_id)` 合并，一页全返回。因为从不跳过任何分片的未消费前缀，晚到的低
  lamport op **永不被跳过**——正是 rank 游标的洞。`limit` 被忽略（本地
  文件读；引擎「空页才停」循环照常终止）。

引擎装完快照后写的续拉哨兵（`v1:{seq}:0`）解成空水位 map → 全量读，是
安全方向（重读由 op_id 去重兜底；永不跳过）。

### 3.3 `push_ops`

追加到本设备的分片。按 `op_id` 对分片已有内容去重（幂等——push 与 ack
之间崩溃无害）。原子写。

## 4. 库级快照：不可变、不物理压缩

服务器在快照上传的同一事务里裁剪被覆盖的 op（`seq ≤ S`）——真压缩。云盘
目录**没有**这种机制（无法在其他设备还持有旧水位时，事务性地删除分片里
的行）。

所以云盘传输：

- 快照写成**不可变**文件 `snapshot-<seq>-<device_id>.bin`（永不覆写；按
  `(seq, device_id)` 内容寻址）；
- `get_library_snapshot` 返回 **max-seq** 文件（多设备并发上传时的确定
  收敛点）；
- `put_library_snapshot` 恒返回 **0**——分片永不物理裁剪。快照是**逻辑**
  检查点：新设备装上它之后只拉增量，但分片保留全量历史作为安全网。

**如实登记的代价**：云盘分片无界增长（服务器的压缩在这里不发生）。对
典型保险库可接受；若真成为问题，后续可以做分片重写 GC（只重写某快照
水位之上的行——本地重写，不是跨设备删除）。

## 5. 组密钥信封（`CloudGroupKeyStore`）

服务器把信封存表里；云盘存文件：

- `register_device(identity)` 追加进 `registry.json`（同设备幂等；同名
  重复拒绝，对应服务器 409）。
- `put_group_key(device_id, envelope)` 写 `env-<device_id>.bin` +
  `env-<device_id>.meta.json`；**设备未登记则失败**（fail-closed，同服务
  器的幽灵设备拒绝）。
- `group_keys()` 读登记表与每个 `env-<device_id>.bin`（已登记但还没有
  信封的设备跳过——即「待授权」态）。
- `bootstrap_group_if_empty` 生成新组密钥、密封给调用方公钥、写自己的
  信封——与服务器同语义。

信封交换是与指令流（`SyncRemote`）分离的 trait（`GroupKeyStore`），
`SyncSession::open_with` 因此能统一装配**任一**传输。`HttpGroupKeyStore`
包装 `SyncAdminApi` 零行为变化；`CloudGroupKeyStore` 是文件版。

## 6. 会话装配

`SyncSession::open_with(db, identity, remote, key_store, travel)` 是传输
无关的装配主体（取信封 → 拆本机信封 → 建引擎）。两种传输都委托它：

- `SyncSession::open`（server）= `open_with(HttpSyncRemote, HttpGroupKeyStore)`
- `SyncSession::open_cloud(db, identity, cloud_dir, travel)` =
  `open_with(CloudDriveRemote, CloudGroupKeyStore)`

`cloud_dir` 是本机上云盘目录的**本地路径**（跨设备分发由 OS 云代理做）。
`open_cloud` 完全不需要服务器 URL 或令牌。

## 7. 配置面

`SyncConfig`（保险库 settings JSON）新增两个字段，都带 serde 默认，旧
JSON 不受影响：

```rust
pub cloud_drive_dir: Option<String>,   // 云盘目录的本地路径
pub sync_transport: SyncTransport,     // Server（默认）| Cloud
```

- `sync_transport` 选择 `sync_now` 用哪条传输；`Server` 是默认（既有行为
  不变）。
- `cloud_drive_dir` 是目录路径（非 secret——存 JSON，不进 keyring）。
- `set_sync_config`（写服务器配置的 Tauri 命令）**保留**这两个字段——
  改服务器设置不得悄悄重置传输选择。

桌面宿主经 Tauri 命令 `set_sync_transport` 接线传输选择（窄写：传输 +
可选目录；空目录保留旧值，云盘须非空）。`open_sync_session` 按传输路由到
server 或云盘会话，云盘设备生命周期（`sync_join` / `sync_leave` /
`sync_list_devices` / `sync_authorize` / `sync_revoke` /
`sync_set_device_remark`）对 UI 可见。设置 UI 两侧齐备：传输选择器
（server / 云盘目录）+ 云盘目录选择器（`@tauri-apps/plugin-dialog`），
落在这两个字段上。

## 8. 传输对比

|                   | Server（persona-server） | 云盘                           |
| ----------------- | ------------------------ | ------------------------------ |
| 基础设施          | 须自建/信任服务器        | 无——一个 OS 云盘目录           |
| seq               | 服务器 AUTOINCREMENT     | 合成 `(lamport, device_id)`    |
| 游标              | rank `(seq, op_id)`      | 每分片行数水位                 |
| 晚到低 lamport op | 不会（服务器序）         | 不会跳过（水位）               |
| 压缩              | 快照裁剪覆盖 op          | 无（不可变、分片 append-only） |
| 快照 CAS          | 409 门控                 | 内容寻址文件名                 |
| 设备名册          | 服务器表                 | `registry.json` + `env-*.bin`  |
| 信任              | 中转零知识               | 供应商只见密文                 |

## 9. 开放问题 / 跟进

1. **桌面设置 UI**（已落地）：设置页渲染传输选择器（server / 云盘目录，
   `SyncTransportSection`）——切到 cloud 但没目录时先弹 OS 目录选择器再
   整体保存；切回 server 保留已配目录。不乐观翻转：写回由服务端返回真相
   回填。
2. **变更 watcher**（已落地）：桌面宿主跑一个监督任务
   （`src-tauri/src/sync_watcher.rs`），每 ~5s 重评同步配置；当传输为
   `cloud` 且目录已配时，监听协议文件（`dev-*.jsonl` / `snapshot-*.bin` /
   `env-*` / `registry.json`）。主源是 `notify`（尽力而为——网络文件系统或
   监听启动失败时静默降级）；轮询兜底是 30s 协议文件 mtime+size 指纹，仅
   在变更时触发。变更后跑一轮完整 `sync_cycle_once`（与 `sync_now` 同编
   排），由 5s 监督节拍去抖，并抑制反馈回路（自身 push 写分片会再触发）
   ——周期后把基线指纹刷到周期末状态。core 保持零新依赖（`notify` 仅
   desktop 依赖）。
3. **分片增长**：无物理压缩（§4）；保险库历史大了之后分片重写 GC 是最终
   解。
4. **云盘目录可用性**（已落地）：目录可达且 OS 代理已分发时同步才有效。
   宿主结构化归类周期失败——传输层 I/O 失败（`PersonaError::Io`）在云盘
   传输下带 `SYNC_CLOUD_FOLDER_UNAVAILABLE`、在服务器传输下带
   `SYNC_SERVER_UNREACHABLE`（写入 `ApiResponse.error_code`，该通道已在
   `CONCURRENT_CONFLICT` 上使用）——设置页据此把「云盘目录不可用」与
   「服务器不可达」区分展示（前者修法是改指存在的目录/查云代理分发，后者
   是查服务器 URL 与令牌）。门禁类失败（锁定/未入组/目录未配置）不带码，
   保持通用提示。
