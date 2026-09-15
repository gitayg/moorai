# Contributing to MoorAI

Thanks for your interest. MoorAI is a security tool, so contributions are held to a high bar for
clarity and safety.

## Ground rules

- **Never commit secrets.** All credentials live in environment variables, never in code. The
  `.gitignore` already excludes `.apple-signing.local`, `AuthKey_*.p8`, `*.db`, and signing keys —
  keep it that way. Run a scan before you push.
- **No raw content leaves the device.** The core privacy invariant: the server stores and receives
  only redacted metadata. Any change that could ship prompt/response content off-device will be
  rejected.
- **Keep detection rules honest.** When you add or change a detector (`data/detectors.js`,
  `data/content-rules.js`) or a threat (`data/threats.json`), include an example that triggers it
  and a note on false-positive risk.

## Workflow

1. Fork and branch from the default branch.
2. Make focused changes — split unrelated work across commits/PRs.
3. Update docs in the same change (README, `docs/`, and this file if relevant).
4. Bump the version before a release-bound change (`server/version.js`, `package.json`,
   `deployhub.json`, `src-tauri/tauri.conf.json`, `src-tauri/Cargo.toml`). See [docs/RELEASE.md](docs/RELEASE.md).
5. Open a PR describing the change and its security impact, if any.

## Local checks

```bash
node --check server/server.js          # syntax
cargo check --manifest-path src-tauri/Cargo.toml
python3 -m http.server 8000            # exercise the webview UI
```

## Licensing of contributions

MoorAI is licensed under **MIT**. By submitting a contribution you agree it is licensed under
the same terms.
