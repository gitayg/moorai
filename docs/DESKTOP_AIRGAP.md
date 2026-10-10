# Desktop app with a self-hosted or air-gapped console

From v1.12.0 the MoorAI desktop app (Tauri, `src-tauri/` + `src/`) works with a console you run
yourself, at any origin. A device provisioned to such a console sends nothing to the MoorAI cloud
(`app.moorai.dev`, `moorai.glick.run`), before or after enrolment.

## Which console the app uses

The webview's console is chosen in this order (`serverBase()` in `src/api.js`):

1. the console the host recorded at enrolment (`console.json` in the host-only `MoorAI Host`
   directory, see `src-tauri/src/console_binding.rs`);
2. the provisioned `serverUrl` in `~/.moorai/config.json`, e.g. written by the Jamf / Intune deploy
   scripts in `packaging/mdm/`;
3. a `raiseme.server` override in the webview's localStorage (https, or http to localhost only);
4. `https://app.moorai.dev`, the MoorAI cloud console.

Step 4 applies only to an unprovisioned consumer install, which is the product's existing behaviour.
Once a device has a recorded console or a provisioned `serverUrl`, the cloud is never used as a
fallback.

Calls that carry the install token always go to the recorded console (step 1). Neither the webview
nor `config.json` can redirect them.

## Enrolling against a self-hosted console

- **MDM:** write `serverUrl`, `tenant` and `installToken` to `~/.moorai/config.json`
  (`packaging/mdm/`). The host records the console on first use.
- **In the app:** paste the console's enrolment link, `https://<your-console>/d/<token>`, into the
  installation-token field. A bare token enrols against the console from the list above.

A console URL must be https. Plain http is accepted only for `localhost`, `127.0.0.1` and `[::1]`
(local development).

## Console calls go through the host, and the CSP names no console

The webview no longer fetches the console itself. Every console call from `src/api.js` (policy,
alerts, prompt events, device and agent-posture reports, enrolment, signup) goes through the host
command `console_fetch` (`src-tauri/src/console_http.rs`):

- **Calls with the install token:** the host picks the recorded console and attaches the token. The
  token never crosses into the webview's request, and the webview cannot name the origin.
- **Calls without a credential** (enrolment, signup, the default policy) go to the origin the webview
  names. No token is attached.
- **Rules for every call:**
  - https only, with plain http allowed for localhost;
  - the request must stay on the console's origin;
  - only the console routes the app uses are allowed;
  - redirects are never followed;
  - each call times out after 4 seconds.

So the CSP's `connect-src` names no console:
`default-src 'self'; connect-src 'self' ipc: http://ipc.localhost https://api.anthropic.com`.
A self-hosted console needs no CSP change and no CORS headers.

## Updates

The updater's endpoints are chosen at runtime, for each check (`src-tauri/src/update_source.rs`):

| Device | Update endpoint |
|---|---|
| Provisioned to a console that is not a MoorAI cloud origin | `<console>/api/update` only |
| Unprovisioned, or on the MoorAI cloud | `https://app.moorai.dev/api/update`, then `https://moorai.glick.run/api/update` |
| Updates turned off | none: no request is made |

**Turning updates off.** Either setting below stops the app from building an updater, so it makes
no network attempt.

- **`~/.moorai/config.json`:** add `"updates": "off"` (or `"updates": false`). Any process running
  as the user can change this file, so it can switch updates off but cannot be relied on to keep
  them off.
- **macOS managed preference:** set the boolean `DisableUpdates` to true in the `run.glick.moorai`
  domain, for example as a Forced key in the existing `MoorAI-config.mobileconfig`. The app reads
  `/Library/Managed Preferences/<user>/run.glick.moorai.plist`, then
  `/Library/Managed Preferences/run.glick.moorai.plist`. These files are root-owned, so a process
  running as the user cannot undo the setting. A managed `true` overrides `config.json`.

Windows and Linux have no managed setting for this yet. Use `config.json`.

**Signatures are unchanged.** Every update must still be signed with MoorAI's updater key (the
`pubkey` in `tauri.conf.json`). A self-hosted console can serve only builds that MoorAI signed. It
cannot sign its own builds and cannot downgrade the app.

The webview no longer holds the `updater:default` permission. Before this change, the webview could
call the updater plugin directly, which bypassed the endpoint choice and the off switch and allowed
downgrades. Now only the host's `check_and_install_update` command runs updates.

Release builds refuse a plain-http update endpoint (`InsecureTransportProtocol` in
tauri-plugin-updater). A production self-hosted console must therefore serve https. Debug builds
accept http with a warning.

### What the console has to serve

`GET /api/update` must return a Tauri v2 updater manifest:
`{ version, notes, pub_date, platforms: { "<os>-<arch>": { signature, url } } }`. It may also return
`204` when no update is available. The MoorAI console builds this manifest from local files and
lists only `darwin-aarch64` today.

To update Windows, Linux or Intel Macs from a self-hosted console, the console also has to:

- serve each platform's updater artifact and its `.sig` from the MoorAI release;
- list those platforms (`windows-x86_64`, `linux-x86_64`, `darwin-x86_64`) in the manifest.

Air-gapped sites have to copy these signed artifacts across manually.

## Other network use

- **OCR provider fallback** (`src-tauri/src/ocr_provider.rs`, `api.anthropic.com`): it runs only on
  a platform with no OS text-recognition engine, only when the caller opts in, and only when a
  provider key is already on the device. Without a key it returns an error before any request is
  made. macOS and Windows always use the on-device engine.
- **Agent CLIs** in the terminal (Claude Code, Codex, Copilot) talk to their own providers. MoorAI
  does not route that traffic.
