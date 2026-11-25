/** Single barrel for the shared desktop types (mirrors the src-tauri command
 * payloads one-to-one).
 *  Split by domain: api/sync/backup/account/credential/ssh/wallet/health;
 *  this file only re-exports, so consumers keep using `@/types` unchanged.
 */
export * from './api';
export * from './sync';
export * from './backup';
export * from './account';
export * from './credential';
export * from './ssh';
export * from './wallet';
export * from './health';
