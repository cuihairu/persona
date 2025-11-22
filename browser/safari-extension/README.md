# Persona Safari Extension Skeleton

This directory captures the files that will back the Safari Web Extension build. The design mirrors the
Chromium extension so we can share JavaScript/TypeScript sources and then wrap them with a macOS host app
via Xcode's “Safari Web Extension” template.

## Layout

- `Shared/manifest.json` – WebExtension manifest, kept intentionally close to the Chromium variant.
- `Sources/PersonaSafariExtensionApp` – SwiftUI host app stub that enables distribution through the Mac App Store.
- `Sources/PersonaSafariExtensionExtension` – Swift bridge that receives messages from Safari and can talk to the host.

Run `xcrun safari-web-extension-converter ../chromium-extension/public` after the Chromium build to populate the
`Shared` folder with the latest JS bundles. The generated Xcode project can live in this directory as well.

## Next steps

1. Wire the Swift host app to bootstrap the shared WebExtension bundle.
2. Bridge messages between Safari JS runtime and the Persona desktop agent via XPC/CLI.
3. Harden entitlements and signing for distribution.
