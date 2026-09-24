# 故障排除

## 解锁与密码

**主密码错误，解不开库**
没有找回途径（无托管、无重置）。若做过加密导出（`persona export
--encrypt`），导入该备份可拿回导出时点的数据；之后的变更无法恢复。

**生物识别解锁不可用**
生物识别只是解锁便利层，主密码始终可用。桌面端生物识别依赖 OS 钥匙串
（service 名 `persona-biometric`）——系统钥匙串被清理后需用主密码重新
解锁并重新托管。

## 库与数据

**怀疑库文件损坏（报错 SQLite/迁移失败）**
用最近的备份恢复（`persona import <备份文件> --decrypt` 或整库 restore）。
快照点之后的本地变更会丢——这是为什么备份要定期做。注意 Windows 上
先确认没有其他 Persona 进程持有库文件。

**误删了身份/凭据**
本地即删。恢复途径同上：restore 到旧备份。日常频繁改动的场景建议
提高备份频率。

## 同步（多设备）

**同步不动了，按链路排查**

1. 服务器活着吗：`curl http://<server>/health` 应返回 200；
2. 这台设备在组里吗：桌面「设置 → 同步设备」看设备列表与授权状态
   （**有信封 = 已授权**；未授权设备不会收到数据）；
3. 手动触发：「立即同步」按钮跑一轮后看错误提示。

**轮换组密钥时报「另一台设备刚刚完成轮换」（409 / CONCURRENT_CONFLICT）**
正常现象：并发轮换被 epoch 乐观锁拒绝，**你的数据不受影响**。稍后
重新点轮换即可（客户端会以新 epoch 重跑）。

**一台设备丢了 / 被盗**
在被授权的另一台设备上**吊销**它（级联清除信封与登录态，即时生效），
然后**轮换组密钥**——被吊销设备拿不到新信封，后续数据对它不可见。

**新设备收不到数据**
确认它已被授权（有信封）；再看服务器 oplog 保留窗口是否 ≥ 该设备
上次在线距现在的时间——离线超窗的历史不会补发，但本地库本身不丢。

## 浏览器扩展与 SSH Agent

**扩展连不上桌面端**
桌面应用必须在运行（Native Messaging 桥接）；检查扩展与桌面的配对
是否建立（重新配对即可重建）。协议细节见
[BRIDGE_PROTOCOL.md](https://github.com/cuihairu/persona/blob/main/docs/BRIDGE_PROTOCOL.md)。

**SSH Agent 拒绝签名**
先看是不是策略在拦：known_hosts 校验、per-key/per-host 确认、速率
限制都会主动拒绝——这是设计行为，不是故障。审计日志里有对应拒绝记录。

## 平台

**macOS / Windows**
未在真机验证，不宣称支持；CLI 理论上可编译但无测试背书。桌面 deb
仅 Linux。

更多背景：[STORAGE_AND_SYNC.md 的故障后果速查](https://github.com/cuihairu/persona/blob/main/docs/STORAGE_AND_SYNC.md)、
[THREAT_MODEL](https://github.com/cuihairu/persona/blob/main/docs/THREAT_MODEL.md)。
