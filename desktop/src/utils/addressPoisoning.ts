/**
 * Heuristic detection of address poisoning.
 *
 * The common attack: an attacker sends a zero-amount / dust transaction so that
 * the history shows a spoofed address "almost identical" to one the user uses
 * often — same prefix and suffix — baiting the user into copying the wrong
 * address from the transaction history.
 *
 * Detection rule: an address whose **first 6 and last 6 characters exactly match
 * a known address while the middle differs** counts as suspected poisoning.
 * Comparisons are lowercased (unambiguous for EVM hex addresses; somewhat
 * conservative for base58 — better to over-report than to miss one).
 */

const HEAD = 6;
const TAIL = 6;

/**
 * @param to Address to check
 * @param known Addresses already known from the user's history (frequent / past receiving addresses)
 * @returns The known address that appears to be imitated; null when there is no suspicion
 */
export const looksLikeAddressPoisoning = (
  to: string,
  known: string[],
): string | null => {
  const t = to.trim().toLowerCase();
  if (t.length < HEAD + TAIL) return null;

  for (const k of known) {
    const kx = k.trim().toLowerCase();
    if (kx === t) continue; // the very same address is not imitating anything
    if (kx.length < HEAD + TAIL) continue;
    if (t.slice(0, HEAD) === kx.slice(0, HEAD) && t.slice(-TAIL) === kx.slice(-TAIL)) {
      return k;
    }
  }
  return null;
};
