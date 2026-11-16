/** 桌面共享类型总出口（与 src-tauri 命令载荷一一对应）。
 *  按域拆分：api/sync/backup/account/credential/ssh/wallet/health，
 *  此处仅 re-export，消费方 `@/types` 路径不变。
 */
export * from './api';
export * from './sync';
export * from './backup';
export * from './account';
export * from './credential';
export * from './ssh';
export * from './wallet';
export * from './health';
