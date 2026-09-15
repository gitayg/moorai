# Packaging & distribution

Two install channels for MoorAI: **npm** (the `moorai-*` CLI tools) and **Homebrew** (the macOS
desktop app). Both are prepared here; publishing needs your accounts and is a manual step (do it only
after the repo is public and the name is secured).

## npm — the CLI tools

`package.json` is already publish-ready: `bin` exposes 16 CLIs (`moorai-scan`, `moorai-aibom`,
`moorai-guard`, `moorai-hook`, `moorai-ledger`, `moorai-redteam`, `moorai-agentwatch`,
`moorai-destinations`, `moorai-trace`, `moorai-shadow`, `moorai-compliance`, `moorai-verify-chain`,
`moorai-stix`, `moorai-honeytokens`, `moorai-attest`, `moorai-receipt`), `exports` exposes
`moorai/scan`, and `files` ships only `scan.mjs cli/ src/ data/ scripts/redteam.mjs
scripts/accepted-failures.mjs test/redteam/corpus.json` (not the Rust/Tauri host). `npm pack
--dry-run` lists 81 files, 457.0 kB packed.

The zero-install entry point is the pre-install skill gate — after publishing, anyone can run:

```bash
npx moorai-scan ./some-skill      # content-free verdict on a skill / MCP config before installing it
npx moorai-aibom --format md      # content-free AI Bill of Materials for the machine
npx moorai-guard -- "prompt"      # pre-flight guard for claude -p
```

**Publish:**
```bash
npm login                          # once, as the account that owns the "moorai" name
npm publish --access public        # from the repo root
```
> Reserve the `moorai` name on npm now (even with a stub) so nobody squats it before launch.
> The package is ESM and the CLIs use global `fetch` (Node 18+); CI builds on Node 20. No `engines`
> field is set. The CLIs import no runtime deps (the two xterm deps are for the desktop webview).

## Homebrew — the desktop app

`homebrew/moorai.rb` is a cask that installs the macOS DMG from `https://moorai.glick.run/download/app`
— the same installer `npm run release` / `release-macos.yml` uploads. GitHub Releases carry no macOS
asset. The build is Apple-silicon only, so the cask declares `depends_on arch: :arm64`.

That URL has no version in it and always serves the latest build, so the cask uses
`version :latest` + `sha256 :no_check` (the Cask Cookbook's case for a `url` with no version
information whose contents change between releases) and `auto_updates true` (the app downloads and
installs its own updates via the Tauri updater).

**The tap:** published at [`gitayg/homebrew-tap`](https://github.com/gitayg/homebrew-tap) as `Casks/moorai.rb`.
This file is the source of truth, so copy any change into the tap repo. Users install with:

```bash
brew install --cask gitayg/tap/moorai
```

Homebrew won't load casks from third-party taps until they are trusted. Installing by the fully qualified name trusts
only this cask. Users who tap first and use the short name need `brew trust --cask gitayg/tap/moorai`.

**Per release:** nothing to change in the cask. Ship the DMG as usual (`npm run release` or a
version tag); `brew install` picks up whatever `/download/app` serves. Edit the cask only if the
download URL, the architecture, the minimum macOS or the zap paths change.

> Optional later: submit to `homebrew-cask` core once there's adoption (they require a notable
> user base). The personal tap works immediately with no such bar.

## PyPI (optional, name protection)

There's no Python package, but reserving `moorai` on PyPI with a stub pointing at the repo prevents
squatting and aids discovery. Low priority; do it when convenient.
