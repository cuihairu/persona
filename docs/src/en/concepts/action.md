# Action

**In one sentence**: an action is the concrete operation applied to a
[material](./material) — reveal, copy, fill, TOTP, generate, sign, save. **Only
actions carry permission semantics**: an SSH key has no permission; the `sign` action
does. A fill has no permission; the `request_fill` action (together with its user
gesture and domain binding) does.

Separating Material from Action has three direct consequences:

- **Clients can work without ever touching plaintext** — the browser extension only
  sends action requests, and core adjudicates and returns the result (or refuses);
  this is "the extension does not own the password" expressed at the protocol layer;
- **Different actions on the same material can have different gates** — viewing a
  password requires re-authentication, autofill happens only when the site is already
  trusted, and signing requires confirmation or biometrics;
- **Audit follows actions** — an audit records "who requested which action in which
  context," not "which entry was read once."

## Current state: the action list and its gates

Crypto actions (bridge protocol message types, all requiring pairing + session HMAC
authentication):

| Action              | Protocol message    | Gate (adjudicated by core)                                                                  |
| ------------------- | ------------------- | ------------------------------------------------------------------------------------------- |
| Suggestions         | `get_suggestions`   | origin + active identity + match strength                                                   |
| Fill                | `request_fill`      | user gesture + origin binding (fetched credential content goes only to the requesting page) |
| TOTP retrieval      | `get_totp`          | user gesture + origin binding                                                               |
| Copy                | `copy`              | user gesture (clipboard handled by desktop/CLI, with 30s auto-clear)                        |
| Passkey creation    | `passkey_create`    | user gesture + desktop approval                                                             |
| Passkey assertion   | `passkey_assert`    | user gesture + desktop approval                                                             |
| Save/update         | `save_credential`   | user gesture + desktop approval (credential_save) + origin binding + audit                  |
| Password generation | `generate_password` | authenticated session; pure generation, nothing stored                                      |

For protocol details, see
[BRIDGE_PROTOCOL](https://github.com/cuihairu/persona/blob/main/docs/BRIDGE_PROTOCOL.md).

Local actions (entry points wired directly to core):

| Action         | Entry point                   | Gate                                                                        |
| -------------- | ----------------------------- | --------------------------------------------------------------------------- |
| reveal         | CLI/desktop                   | unlock + re-authentication for sensitive operations + 30s auto-hide         |
| SSH signing    | SSH Agent                     | policy engine: known_hosts, confirmation, rate limits, biometric precedence |
| Export         | `persona export`              | unlock + confirmation of the target encryption policy                       |
| Wallet signing | desktop/wallet (experimental) | confirmation modal: address/amount/chain plus an address-poisoning warning  |

## Plans

- Each action's allow/confirm/deny triple can be customized by the
  [rule layer](./policy#vision-the-rule-layer-planned-not-implemented);
- Future [Principals](./principal) (Agents) will receive **per-action allowlists**
  (for example, codex may only perform `git`-related signing and is forbidden from
  wallet signing) without ever obtaining the materials themselves.
