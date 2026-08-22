# Code signing & notarization (macOS)

The build is already wired for Developer ID signing + notarization — it activates
automatically when these environment variables are present at `tauri build` time.
Until then, builds are adhoc-signed (Gatekeeper warns on first open).

**This account is already enrolled and the certificate is installed** (the same
Developer ID used to ship the AgentClub desktop app):

| Value | Setting |
|---|---|
| Developer ID | `Developer ID Application: Itay Glick (DA4PX65QXV)` |
| Team ID | `DA4PX65QXV` |
| Apple ID | `gitayg@gmail.com` |
| App-specific password | generate at appleid.apple.com (or reuse the AgentClub one) — **never commit it** |

## One-time setup

The Developer ID Application cert is already in this Mac's login keychain — confirm:
```
security find-identity -v -p codesigning
# → "Developer ID Application: Itay Glick (DA4PX65QXV)"
```
The only thing to create is an **app-specific password** for notarization at
appleid.apple.com (Sign-In & Security → App-Specific Passwords). Keep it out of
git — set it as an env var or a GitHub secret only.

## Build a signed + notarized app

Set these and run the normal build — Tauri signs with the identity, then submits
to Apple's notary service and staples the ticket:

```bash
export APPLE_SIGNING_IDENTITY="Developer ID Application: Itay Glick (DA4PX65QXV)"
export APPLE_ID="gitayg@gmail.com"
export APPLE_PASSWORD="xxxx-xxxx-xxxx-xxxx"   # app-specific password (do not commit)
export APPLE_TEAM_ID="DA4PX65QXV"

npm run release        # signs → notarizes → staples → DMG (or: npx tauri build --bundles app,dmg)
```

The hardened runtime + `entitlements.plist` are applied automatically. Verify:

```bash
codesign -dv --verbose=2 "src-tauri/target/release/bundle/macos/MoorAI.app"   # Authority=Developer ID …
xcrun stapler validate "src-tauri/target/release/bundle/dmg/MoorAI_0.8.16_aarch64.dmg"
```

A notarized, stapled DMG opens with **no Gatekeeper warning**.

## CI (auto-sign on a version tag)

The `release-macos` workflow signs + notarizes automatically once these secrets
exist on `gitayg/moorai` (Settings → Secrets and variables → Actions). Until they
are set, the workflow skips the macOS build with a warning.

| Secret | Value |
|---|---|
| `APPLE_SIGNING_IDENTITY` | `Developer ID Application: Itay Glick (DA4PX65QXV)` |
| `APPLE_TEAM_ID` | `DA4PX65QXV` |
| `APPLE_ID` | `gitayg@gmail.com` |
| `APPLE_PASSWORD` | app-specific password |
| `APPLE_CERTIFICATE` | base64 of the Developer ID `.p12` — `base64 -i cert.p12 \| pbcopy` |
| `APPLE_CERTIFICATE_PASSWORD` | the `.p12` export password |

Export the `.p12` from Keychain Access → the "Developer ID Application: Itay Glick
(DA4PX65QXV)" identity → right-click → Export. Then push a version tag; CI builds,
signs, notarizes, staples, and publishes the DMG.

## Publish

Copy the notarized DMG to `dist/MoorAI.dmg`; the server serves it from
`/download/app`. (CI does this on a version tag once the secrets above are set.)
