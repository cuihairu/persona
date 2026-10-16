# Brand Guidelines

> [English](brand-guidelines.md) | [中文](brand-guidelines.zh.md)

Name and pronunciation

- Public name: Persona（数钥）
- Chinese reading: shù yào
- Usage advice: formal copy and product pages may use "Persona（数钥）"; developer docs and the CLI keep the plain English "Persona" for consistency.

Logo and clear space

- Main logo file: `docs/branding/logo.svg`
- Minimum size: 24×24 px (screen), 12 mm (print)
- Clear space: at least the viewfinder line weight on all sides (the current logo shape is a recognition viewfinder + portrait)
- Not allowed: stretching/distortion, low-contrast backgrounds, clashing saturated backgrounds

Horizontal wordmark

- File: `docs/branding/wordmark-horizontal.svg`
- Recommended for headers / navigation / welcome pages; keep the aspect ratio when scaling

Colors

- See `docs/branding/color-palette.md`
- Gradient primary: `#4C6FFF` → `#00D1B2`
- Adapts to light/dark mode; watch text and background contrast

Icon export advice

- App icon: export multi-size PNG/ICO from `logo.svg` (16/32/48/64/128/256/512)
- Desktop app (Tauri): place under `desktop/src/assets/brand/` and reference it in the packaging config
- Favicon: export 32×32 / 48×48 and keep the SVG version for high-DPI scaling

Naming and path stability

- The visual pass may be replaced before production, but keep the same file paths so existing references keep working
