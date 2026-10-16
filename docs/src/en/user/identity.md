# Identity

**In one sentence**: an identity is a **named group** inside your vault, plus a
pointer saying "which one is currently selected". It is the unit of organization
and switching — **not** an account, **not** a key, **not** an encryption
boundary.

Many people see "Select Identity" in the top bar for the first time and assume it
works like a browser's "profile/account switcher". That leads to a pile of wrong
expectations (for example, thinking switching identity means switching to a
different encryption space). This page explains what it really means.

## Data Model

An identity is one row in the `identities` table in SQLite
(`core/migrations/001_initial.sql`):

| Field                             | Meaning                                                                                |
| --------------------------------- | -------------------------------------------------------------------------------------- |
| `id`                              | UUID, primary key                                                                      |
| `name`                            | The name you give it; both the CLI and the desktop app use it to refer to the identity |
| `identity_type`                   | `Personal` / `Work` / `Social` / `Financial` / `Gaming` / custom                       |
| `description` / `email` / `phone` | Free-form notes, for recognition only; **not involved in any authentication**          |
| `ssh_key` / `gpg_key`             | Note fields — just a pasted blob of public key text, **not** managed keys              |
| `tags` / `attributes`             | Custom tags and key-value pairs                                                        |
| `is_active`                       | Legacy field; current code does **not** use it for filtering (see below)               |
| `travel_marked`                   | Travel-mode flag: this identity travels with you (added in migration 013)              |

Other tables attach to an identity via the `identity_id` foreign key
(`ON DELETE CASCADE`):

```
identities ──┬── credentials        (password / TOTP / API key / SSH key entries)
             ├── crypto_wallets     (crypto wallets)
             ├── passkeys           (passkeys)
             ├── workspace_members  (workspace members; the identity is the "share unit")
             └── workspaces.active_identity_id (the one and only "current identity" pointer)
```

Attachments (`attachments`) do not attach directly to an identity — they attach
to a credential (`credential_id`) — so they belong to an identity together with
that credential.

## The Four Things an Identity Actually Does

### 1. Grouping and View Filtering

The credential list is filtered by `identity_id`
(`PersonaService::get_credentials_for_identity`). Switch to the "Work" identity
and only work-related credentials remain in the UI. This is the primary use of
an identity.

### 2. The Switching Pointer

`persona switch <name>` and the desktop top-bar switcher ultimately do exactly
one thing: rewrite the single field `workspaces.active_identity_id`.

Because the pointer lives in the vault rather than in some client's local state,
the CLI, desktop app, browser extension, and SSH Agent all share the same
"current identity" — switch it anywhere and every other client reads the new
value next time.

### 3. The Travel-Mode Packing Unit

This is the most practical hidden use of an identity. Once `travel_marked` is set
and you enter travel mode, that identity plus the credentials, wallets,
passkeys, attachments, and member rows hanging off it are packed into an
encrypted sidecar and deleted from the local database (`core/src/travel.rs`);
leaving travel mode restores everything as it was.

So an identity is the smallest unit for "take this whole set of materials with
you / leave it behind" — more useful than a single entry.

### 4. Classification Label

`identity_type` only drives presentation: icons, colors, filter groupings. It
has no permission or security meaning; red or yellow, it changes nothing.

## What an Identity Does **Not** Do (Common Misconceptions)

| Misconception                                                    | Fact                                                                                                                                                                                                                                                                   |
| ---------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Switching identity = switching encryption space                  | No. Each credential is encrypted with its own item key, which is then wrapped by the master key derived from the master password (see [Key Hierarchy](https://github.com/cuihairu/persona/blob/main/docs/KEY_HIERARCHY.md)). Identities play no part in key derivation |
| Switching identity requires re-unlocking / a new master password | No. Unlock state is determined by the master password; switching identity neither unlocks nor re-encrypts                                                                                                                                                              |
| An identity carries SSH / GPG private keys                       | No. `ssh_key` / `gpg_key` are just note text. Private keys are separate credential entries (`CredentialType::SshKey`), provided on demand by the SSH Agent                                                                                                             |
| The SSH Agent only offers the current identity's keys            | No. The `--identity` parameter of `persona ssh` is annotated in the code as "reserved for future use" and currently does not filter                                                                                                                                    |
| `identities.is_active` is the current identity                   | No. The field exists but no query filters on it. The current identity is `workspaces.active_identity_id`                                                                                                                                                               |
| An identity has a remote account / login session                 | No. An identity is purely local data. Remote capabilities (sync, server side) are configured separately via `persona connect` and are unrelated to identities                                                                                                          |

## Why There Is No Default Identity on First Launch

`persona init` / first-time desktop initialization does **not** seed any
identity — identities are groups you create yourself, and inventing a "Personal"
one out of thin air would be writing data into your vault that you never asked
for.

Once an identity exists, the frontend auto-selects: it prefers the workspace's
active identity, falls back to the first one, and writes it back as active
(`loadIdentities` in `usePersonaService.ts`). So:

- The top bar showing the "Select Identity" placeholder means you currently
  have **no identities at all** (a new vault) — this is the normal empty state;
- The placeholder still showing after you have created identities means loading
  failed — see [Troubleshooting](./troubleshooting).

If you want it to work out of the box, the first identity you create is
immediately selected as the current one; if you want a fixed default, set it
explicitly with `persona switch`.

## How to Use It

### CLI

```bash
persona add alice --identity-type Personal          # create an identity (NAME is a positional argument)
persona add alice --set-active                      # create it and switch to it right away
persona list                                         # list all identities
persona show <name>                                  # show details
persona switch <name>                                # switch to that identity (global effect)
persona switch --previous                            # switch back to the previous one
persona switch --interactive                         # interactive selection
persona edit <name> --identity-type Work             # change type/notes
persona remove <name> --backup                       # delete (see the warning below)

# CLI credential creation must explicitly name the owning identity (--identity / --name are both required;
# only the desktop "New Credential" dialog defaults to the current identity)
persona credential add --identity alice --name "GitHub" \
  --credential-type password --prompt-secret
persona credential list --identity alice
```

### Desktop App

- Switch via the top-bar identity dropdown or by clicking in the sidebar;
- New credentials are automatically filed under the **current identity** (the
  dialog has no identity dropdown — switch identity first, then create);
- Manage identities in the settings panel: create, edit, delete, toggle the
  travel flag.

## Three Things That Are Easy to Confuse

"Identity" appears in both the code and the UI, and it refers to three things:

| Name                                 | What it is                                                                                                           | Example                                      |
| ------------------------------------ | -------------------------------------------------------------------------------------------------------------------- | -------------------------------------------- |
| **Identity (this page)**             | A credential group + the current-identity pointer; a vault-level entity shared across clients                        | `persona switch alice`                       |
| **Identity-type credential**         | A **credential type** that stores personal details like name, address, ID numbers (the same-named 1Password feature) | Choose "Identity" when creating a credential |
| **Device identity / DeviceIdentity** | Each machine's own key pair, used for sync oplog signing                                                             | Generated automatically; invisible to users  |

The "Identity" option in the new-credential dialog is the **second** kind
(ID-document details), not the identity group this page describes. As a side
note: an ID-type credential itself also belongs to some identity group, so one
identity can hold both "alice's work identity" and "alice's ID document details".

## What Deleting an Identity Cascades To

Deleting an identity makes the `ON DELETE CASCADE` foreign key delete its
credentials, crypto wallets, passkeys, and workspace member rows; deleting a
credential in turn removes the attachment files hanging off it (attachment
ciphertext is sealed under that credential's item key, so keeping them would
leave them undecryptable anyway).

**The audit log is preserved**: before deletion, the `identity_id` references
on audit rows are nulled out, so history is not lost. But the deleted
credential contents are unrecoverable — run `persona export` before deleting.

## Related Pages

- [Quick Start](./quick-start) — create a vault, create your first identity
- [Desktop App](./desktop) — the switcher and the stats page
- [Core Features](../overview/features) — identity-scoped views
- [Key Hierarchy](https://github.com/cuihairu/persona/blob/main/docs/KEY_HIERARCHY.md) — which layer the encryption actually lives in
