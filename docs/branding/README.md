# Persona Brand Assets

> [English](README.md) | [中文](README.zh.md)

Path overview

- docs/branding/logo.svg – main logo (vector, viewfinder + portrait; replaced with the user-provided icon on 2026-09-26)
- docs/branding/wordmark-horizontal.svg – horizontal wordmark (Persona 数钥)
- docs/branding/color-palette.md – color spec and usage advice
- docs/branding/brand-guidelines.md – brand usage rules (sizes, clear space, contrast)

Recommended usage

- Prefer `logo.svg` as the source file for app icons, splash screens and the website favicon (export to multi-size PNG/ICO).
- Use `wordmark-horizontal.svg` for document headers and site navigation.
- For color values see `color-palette.md`; mind the contrast in light and dark modes.

Notes

- Since 2026-09-26 the main logo is the user-provided viewfinder + portrait icon (#99A9BF),
  mirrored into `docs/src/public/persona-logo.svg` (the docs-site favicon / nav /
  home hero all share that path). It can be swapped for a professional visual pass before
  official release, but keep the path unchanged for compatibility with existing references.
