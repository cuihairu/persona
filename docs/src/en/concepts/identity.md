# Identity

**In one sentence**: an identity — "分身" (persona) in the product's Chinese — is one
digital identity of a single person; it is the **unit that organizes, switches, and
packs** identity material. It is not an account, not a key, and not an encryption
boundary.

```text
Person
 └─ Identity: Work
      ├─ GitHub (password)
      ├─ AWS (API key)
      └─ Work SSH
 └─ Identity: OpenSource
      ├─ GitHub (password, a different set)
      └─ Open-source GPG
```

The same GitHub under different identities is a **different credential entry** —
identity isolation happens at the data layer, not by asking you to remember "two
browsing profiles."

## Data model

An identity is a row in the SQLite `identities` table; the other identity material
tables attach beneath it via the `identity_id` foreign key (`ON DELETE CASCADE`):

```
identities ──┬── credentials        (password / TOTP / API key / SSH key / wallet entry)
             ├── crypto_wallets
             ├── passkeys
             ├── workspace_members  (workspace membership: identity is the "sharing unit")
             └── workspaces.active_identity_id (the single "current identity" pointer)
```

For full field lists, migration table names, and common misconceptions, see
[User Guide: Identity](/en/user/identity).

## Where it sits in the authorization chain

In the model from [Core Concepts](./index), Identity receives from Principal and
carries Material below it:

```text
Principal → Identity → Material
   (who)   (which identity)  (which materials)
```

One key property: **identity does not participate in key derivation**. Each credential
is encrypted with its own item key, which is in turn wrapped by the master key derived
from the master password — switching identities never unlocks anything, never
re-decrypts anything, and never changes the encryption boundary. So an identity is a
logical grouping, not a separate safe.

## Two hidden semantics of an identity

1. **Global switch pointer**: `workspaces.active_identity_id` lives in the database;
   the CLI, desktop, browser extension, and SSH Agent all share the same "current
   identity" — a `persona switch` in any one place is what every other entry point
   reads next time.
2. **The packing unit for travel mode**: identities marked `travel_marked` are packed
   whole into an encrypted sidecar and moved off the machine (core/src/travel.rs) — the
   minimal unit for "take the whole set / leave the whole set."

## Boundaries

- Identities **share no authorization** with each other: one identity's credentials
  never appear in another identity's suggestions.
- `identity_type` (Personal/Work/…) only drives presentation; **it carries no
  permission or security meaning**.
- Remote capabilities (sync, server-side) are configured separately through
  `persona connect` and are independent of identities.
