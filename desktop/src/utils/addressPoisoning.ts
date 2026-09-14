/**
 * 地址投毒（address poisoning）启发式检测。
 *
 * 常见攻击：攻击者发送 0 转账/粉尘交易，让历史记录里出现一个
 * 「前缀+尾缀与用户常用地址几乎相同」的伪造地址，诱导用户从
 * 交易历史复制错误地址。
 *
 * 检测规则：与任一已知地址 **前 6 位和后 6 位完全相同但中段不同**
 * 即视为疑似投毒。比较统一转小写（EVM hex 地址无歧义；对 base58
 * 会偏保守——宁可误报也不放过）。
 */

const HEAD = 6;
const TAIL = 6;

/**
 * @param to 待检查的目标地址
 * @param known 用户历史中已知的地址（常用地址/历史收款地址）
 * @returns 疑似被模仿的已知地址；无嫌疑返回 null
 */
export const looksLikeAddressPoisoning = (
  to: string,
  known: string[],
): string | null => {
  const t = to.trim().toLowerCase();
  if (t.length < HEAD + TAIL) return null;

  for (const k of known) {
    const kx = k.trim().toLowerCase();
    if (kx === t) continue; // 同一地址不构成模仿
    if (kx.length < HEAD + TAIL) continue;
    if (t.slice(0, HEAD) === kx.slice(0, HEAD) && t.slice(-TAIL) === kx.slice(-TAIL)) {
      return k;
    }
  }
  return null;
};
