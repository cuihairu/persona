# Introduction

## Background

In today's digital world, one person routinely uses different keys and credentials across
many contexts: work, personal, server access, browser logins, automation scripts, and even
wallet scenarios on the horizon. These are not "different people" — they are different
personas ("分身") of the same person.

Existing identity-management approaches, however, come with plenty of problems:

- **Fragmented management**: keys and credentials for different contexts are scattered
  across browsers, terminals, files, and tools
- **Privacy leaks**: centralized storage creates data-breach risk
- **Painful switching**: switching between personas is cumbersome and error-prone — easy to
  grab the wrong key
- **Blurred boundaries**: material for different purposes of the same person easily
  cross-contaminates
- **Security hazards**: password reuse, weak authentication, wrong-key signing, and
  mistaken autofill all coexist

## The Solution

Persona exists to solve these problems. It is a **local-first, end-to-end encrypted
multi-persona digital identity runtime**: each persona (Identity) of the same person holds
its own identity material (Material); actions (Action) on that material — reveal / fill /
sign — are uniformly adjudicated by policies (Policy), and suggested and switched within
contexts (Context).

In one sentence: **Password, SSH, TOTP, Wallet, and Passkey are identity material, not a
feature list; 1Password-grade capability is the functional baseline, not the product
narrative.**

For the full positioning, product boundaries, tiered security, and authorization model,
see [Product Positioning and Overall Architecture](/en/design/product).

### Multi-Persona Management

- Create and manage multiple identity personas for the same person
- Each persona owns an independent set of identity material
- Per-context suggestions, switching, and default selection

### Local-First and End-to-End Encryption

- Encryption and key derivation happen entirely locally; the default is fully offline
- End-to-end encrypted sync is already implemented: the server only relays ciphertext and
  cannot decrypt credential contents
- The server still sees metadata (events, timestamps, resource IDs, sync information) —
  for the precise wording see
  [Terminology](#terminology-why-end-to-end-encrypted-and-not-zero-knowledge) below

### One-Click Switching

- Switch quickly between personas
- Autofill the matching credentials
- Keep a unified context across browser, CLI, desktop, and SSH scenarios

## Core Philosophy

Identity material belongs to the user: it is stored encrypted locally, and storage, use,
switching, and signing are all governed by the user and by policies. Sensitive data is
decrypted only on the device; with sync enabled, the server relays nothing but ciphertext
and metadata.

## Core Concepts

Persona's entire design rests on six first-class concepts: **persona (Identity), context
(Context), material (Material), policy (Policy), and action (Action)**, plus the reserved
principal (Principal). See [Core Concepts](/en/concepts/index) — that set of documents is
Persona's theoretical foundation: how the concepts are separated, where each lands in the
code, and what remains planned.

## Encryption and Unlocking

- Whole-vault encryption: the master password derives a key via Argon2id, and AES-256-GCM
  encrypts the entire database. A lost master password cannot be recovered by any means.
- Sync channel: the server relays only ciphertext and metadata and takes no part in
  decryption; even if the server is compromised, all an attacker gets is ciphertext.
- Unlock methods: the master password is the foundation; biometric unlock on desktop is
  implemented, with providers dispatched per OS (e.g., the Linux Secret Service).
- Action adjudication: reveal / fill / sign are controlled policy-by-policy on every
  invocation (see [Action](/en/concepts/action) and [Policy](/en/concepts/policy)), with
  context-based persona suggestions.

## Terminology: Why "End-to-End Encrypted" and Not "Zero-Knowledge"

"Zero-knowledge" is easily read as "the server knows nothing," but in fact the server can
see events, timestamps, device information, resource IDs, and sync metadata. This site
settles on the following terminology:

- **Local-first + E2EE**: all encryption and decryption happens on the user's devices; the
  server touches only ciphertext or event digests and cannot decrypt credential contents.
- **Zero-knowledge, scoped to credential storage**: no party — neither the local software
  nor the server — can read plaintext without the master password. That a lost master
  password is unrecoverable is a direct consequence of this property (see
  [FAQ](/en/user/faq)).

Across this site, the wording is uniformly "local-first + end-to-end encrypted";
"zero-knowledge" appears only as a qualifier of storage semantics.

## Use Cases

### Individual Users

- Isolate work and personal personas
- Manage browser accounts and TOTP
- Secure logins and key isolation for online services

### Developers

- Manage SSH keys, API keys, TOTP, and web logins in one place
- Switch personas across projects, clients, and environments
- Use identity material safely in automation and terminal scenarios

## Vision

One identity boundary across desktop, browser, CLI, and SSH: each persona's keys and
credentials are stored encrypted locally; switching personas never changes the material;
actions (reveal / fill / sign) are adjudicated policy-by-policy. Agents (Claude Code / Codex
/ CI) entering the same model as controlled principals is a
[reserved direction](/en/concepts/principal), with no implementation commitment.

First organize, protect, and authorize "multiple personas of one person and their identity
material" — then talk about bigger platforms. The model can grow upward into an identity
runtime; downward it stays local-first and end-to-end encrypted.
