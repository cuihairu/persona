# Persona Boundary

## Product Definition

Persona is a local-first, zero-knowledge identity-material manager for one person operating multiple digital selves.

The system does not model "multiple people" or a generic social identity graph. It models one principal carrying multiple identity contexts, where each context holds a distinct set of keys and credentials used in different digital environments.

## Core Concepts

### Principal

The real person using Persona.

### Identity

An identity is a digital self used by the same principal in a specific context.

An identity is not:
- a different natural person
- a social profile aggregator
- a generic profile card full of unrelated personal data

An identity is:
- a boundary for key material and credentials
- a selectable context for authentication and signing
- a unit for policy, audit, and default selection

### Identity Material

Identity material is the set of secrets and related metadata attached to one identity.

Examples:
- website credentials
- API keys
- TOTP secrets
- SSH keys
- wallet keys or wallet seed material

These materials differ by usage protocol, but share the same core lifecycle:
- secure local storage
- identity scoping
- context-based selection
- controlled reveal, fill, or signing
- audit and policy enforcement

## In Scope

The current product boundary includes:

- multiple identity creation, switching, and active-context persistence
- credential management for passwords, API keys, TOTP, SSH keys, and related secure notes
- browser-assisted flows such as autofill, suggestion, domain matching, and phishing resistance
- desktop and CLI workflows for viewing, managing, and switching identity material
- developer workflows such as SSH agent integration and automation-friendly access
- local-first security primitives such as encryption, auto-lock, confirmation, and audit logging

## Out of Scope

The current product boundary does not include:

- enterprise IAM, SSO, SCIM, or RBAC
- social identity aggregation or public identity publishing
- generic cloud-first sync platform design
- plugin-platform-first architecture
- machine-learning-driven identity recommendation as a core product need
- broad "digital identity platform" positioning

## Wallet Position

Wallet material is conceptually inside the same model as SSH keys and other credentials because it is still identity material bound to one digital self.

However, wallet support is not a current product priority.

Current status:
- conceptually in-boundary
- roadmap priority deferred
- implementation treated as experimental or later-stage work

This means wallet support should not define the current roadmap, UI priority, or platform abstractions unless it directly helps the primary identity-material workflows already in use.

## Prioritization Rule

New work should be prioritized only if it clearly improves at least one of these:

- switching between identity contexts
- managing identity-scoped credentials or keys
- browser, desktop, CLI, or SSH workflows
- local security controls around reveal, fill, or signing

If a proposal does not strengthen those workflows, it should not enter the mainline roadmap.

## Practical Test

Use these questions before accepting new scope:

1. Does this directly improve identity switching or identity-scoped material management?
2. Does this directly strengthen the browser, desktop, CLI, or SSH core loop?
3. Would Persona still be complete as a product if this feature were omitted?

If the first two answers are both "no", the work is outside the current mainline boundary.
