---
layout: home

hero:
  name: Persona
  text: Multi-persona digital identity runtime
  tagline: Master your digital identity. Switch freely with one click.
  image:
    src: /persona-logo.svg
    alt: Persona logo
  actions:
    - theme: brand
      text: Get Started
      link: /en/user/quick-start
    - theme: alt
      text: View Architecture
      link: /en/overview/architecture
    - theme: alt
      text: GitHub
      link: https://github.com/cuihairu/persona

features:
  - title: Local-first and end-to-end encrypted
    details:
      Sensitive identity material is decrypted only on your devices; the server sees
      only ciphertext and metadata, and can never decrypt any credential.
  - title: Multiple personas, separate contexts
    details:
      Keep work, personal, development, SSH, and browser identity material isolated
      per scenario and switch between them.
  - title: One consistent boundary across platforms
    details:
      The CLI, desktop app, browser extension, and SSH Agent share the same local
      service and policies.
---

## Interface Previews

<UiCarousel />

A carousel of desktop light and dark themes, sidebar details, and mobile screens. For more
screenshots and asset credits, see [UI Previews](/en/previews/ui) and
[Asset Inventory](/en/previews/assets).

## Start Here

- [Get Started](/en/user/quick-start) Build the desktop app or CLI and create your first
  encrypted password vault.
- [Introduction](/en/overview/introduction) Understand the problem boundary and design
  philosophy behind Persona.
- [Core Concepts](/en/concepts/index) Persona (分身, persona), context, material, policy,
  action — the conceptual foundations of Persona.
- [Architecture](/en/overview/architecture) Explore the layered structure and the
  end-to-end encrypted sync design.
- [Security Design](/en/design/security) Key hierarchy, threat model, and security
  boundaries.
- [Project Structure](/en/development/structure) Set up local development and browse the
  monorepo layout.
- [Engineering Docs](https://github.com/cuihairu/persona/tree/main/docs) In-depth
  documentation on E2EE sync design, threat model, reproducible builds, and more.
