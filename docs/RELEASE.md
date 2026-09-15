# Releasing

One command does everything: bump → build the app + DMG → upload the installer to
AppCrane's `/data` volume → push the server code → deploy → verify.

```bash
npm run release          # re-ship the current version
npm run release patch    # x.y.Z+1, then ship
npm run release minor    # x.Y+1.0, then ship
npm run release 1.0.0    # set an exact version, then ship
```

The bump updates `server/version.js`, `package.json`, `deployhub.json`,
`src-tauri/tauri.conf.json`, and `src-tauri/Cargo.toml` together, so the host,
server, and installer always report the same version (no false update prompts).

It verifies on the way out: production health must report the new version, and
`/download/app` must return the exact bytes that were just built (sha256 checked).

## Auto-update artifacts

Besides the DMG, the release uploads three blobs to AppCrane `/data` (and keeps
copies in `dist/`, which the server falls back to in dev):

| Blob | Content |
|---|---|
| `MoorAI.app.tar.gz` | the updater bundle |
| `MoorAI.app.tar.gz.sig` | its updater signature |
| `MoorAI.app.tar.gz.version` | the released desktop version as plain text plus a newline, e.g. `0.83.3` |

The version sidecar exists because the server's updater manifest (`/api/update`)
has to advertise the **desktop** version. The updater only installs when that
version is newer than the installed one. Without the sidecar the server can only
report its own, unrelated version, so installed apps stop updating.

The sidecar is uploaded last, after the tarball and signature succeed, so a failed
upload never advertises a version whose artifact isn't there. The logic lives in
`scripts/release-updater.mjs` and is covered by `test/release-updater.test.mjs`.

## Signing

If `APPLE_SIGNING_IDENTITY`, `APPLE_ID`, `APPLE_PASSWORD`, and `APPLE_TEAM_ID` are
exported, the build is signed + notarized automatically (see `docs/SIGNING.md`).
Otherwise the DMG is adhoc and macOS warns on first open.

## Credentials

The AppCrane key comes from `APPCRANE_API_KEY`, or the untracked
`.appcrane-key.local` file (gitignored). Keep it out of source control.
