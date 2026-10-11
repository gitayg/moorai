# Desktop app with a self-hosted or air-gapped console

The MoorAI desktop app (Tauri, `src-tauri/` + `src/`) works with a console you run yourself, at any
origin. A device provisioned to such a console by an administrator sends nothing to the MoorAI cloud
(`app.moorai.dev`, `moorai.glick.run`), before or after enrolment.

## Which console the app uses

`~/.moorai/config.json` and the webview's localStorage are writable by any process running as the user,
including the agent MoorAI guards. So neither decides where the install token goes, where updates come
from, or whether updates run. Three sources do:

- **The recorded console.** The host records the console in `console.json` in the host-only `MoorAI Host`
  directory (`src-tauri/src/console_binding.rs`) when the device enrols in the app. An install enrolled
  before that file existed, or provisioned by an MDM script that writes `config.json`, has its
  `config.json` console recorded once, on first use.
- **The administrator-provisioned console** (`src-tauri/src/admin_config.rs`):
  - on macOS, the managed preference `ServerURL` in the `run.glick.moorai` domain, as
    `packaging/mdm/jamf/MoorAI-config.mobileconfig` sets it
    (`/Library/Managed Preferences/<user>/run.glick.moorai.plist`, then
    `/Library/Managed Preferences/run.glick.moorai.plist`). `<user>` is the login name of the app's user
    ID from the user database, not `USER`, `LOGNAME` or `HOME`, which whoever starts the app sets. A name
    containing `/`, `\`, `..` or NUL drops the per-user path;
  - on macOS and Linux, `serverUrl` in `/etc/moorai/config.json`;
  - on Windows, `serverUrl` in `<ProgramData>\MoorAI\config.json`, read only when its ACL lets nobody but
    Administrators, SYSTEM or TrustedInstaller write it. ProgramData and the `icacls.exe` directory come
    from HKLM, not from the `ProgramData` and `SystemRoot` environment variables. The file is held open
    without write or delete sharing from the ACL check to the read, and a symlink or junction at the file
    is refused.

  On macOS and Linux each of these files is read only when its directory, after resolving symlinks, lies
  under `/Library/Managed Preferences` or `/etc/moorai`; that directory and every directory above it is
  owned by root and not group- or world-writable; and the file is not a symlink, is owned by root and is not
  group- or world-writable. The ownership and mode are checked on the open file, which is then the one
  read. A plist is passed to `/usr/bin/plutil` on stdin. A file that fails any check is ignored.
- **The MoorAI cloud**, `https://app.moorai.dev`, for an unprovisioned consumer install.

The webview uses them as follows (`src/api.js`):

| Call | Console |
|---|---|
| Calls with the install token (policy, alerts, prompt events, device and agent-posture reports) | the recorded console only |
| Enrolment with a bare token, and in-app signup (`enrolBase()`) | the administrator-provisioned console, else the recorded console when an enrolment in this app recorded it, else the cloud |
| Enrolment with a link, `https://<console>/d/<token>` | the console in the link |
| The default policy of an unenrolled device (`serverBase()`) | the administrator-provisioned console, else the recorded console, else as for enrolment |

A recorded console that came from the first-use record of `config.json` is not where a bare token goes,
because on a device that never enrolled the agent can have planted that `config.json`. localStorage's
`raiseme.server` plays no part in the desktop app: it lives in WebKit storage under the user's home
(`~/Library/WebKit/<bundle id>/` on macOS), which the agent can write. Only the plain-browser build, which
has no host to record a console, still reads it. A device provisioned by an administrator never falls back to the
cloud. A device whose MDM writes only `config.json` keeps its recorded console for every credentialed call
and for updates; to keep a bare-token re-enrolment or a signup off the cloud too, also set the managed
`ServerURL` or the machine file's `serverUrl`.

## Enrolling against a self-hosted console

- **MDM:** write `serverUrl`, `tenant` and `installToken` to `~/.moorai/config.json`
  (`packaging/mdm/`). The host records the console on first use. Set the console in the managed
  preference `ServerURL` (macOS) or the machine file as well, so the app uses it before enrolment and for
  updates whatever `config.json` says later.
- **In the app:** paste the console's enrolment link, `https://<your-console>/d/<token>`, into the
  installation-token field. A bare token enrols against `enrolBase()` above.

A console URL must be https. Plain http is accepted only for `localhost`, `127.0.0.1` and `[::1]`
(local development).

## Console calls go through the host, and the CSP names no console

The webview does not fetch the console itself. Every console call from `src/api.js` (policy,
alerts, prompt events, device and agent-posture reports, enrolment, signup) goes through the host
command `console_fetch` (`src-tauri/src/console_http.rs`):

- **Calls with the install token:** the host picks the recorded console and attaches the token. The
  token never crosses into the webview's request, and the webview cannot name the origin.
- **Calls without a credential** (enrolment, signup, the default policy) go to the origin the webview
  names, chosen as in the table above. No token is attached.
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
| Administrator-provisioned console (managed `ServerURL` or the admin-owned machine file), or a console the user enrolled to in the app, that is not a MoorAI cloud origin (the administrator's wins) | `<console>/api/update` only |
| Unprovisioned, on the MoorAI cloud, or bound only by first-use migration of `~/.moorai/config.json` (that file is user- and agent-writable, so it never chooses the update source; MDM deployments set `ServerURL` instead) | `https://app.moorai.dev/api/update`, then `https://moorai.glick.run/api/update` |
| Updates turned off by an administrator | none: no request is made |

`serverUrl` and `updates` in `~/.moorai/config.json` play no part: a value planted there neither points
update checks at another server nor stops them.

**Turning updates off.** Either administrator setting below stops the app from building an updater, so it
makes no network attempt.

- **macOS managed preference:** set the boolean `DisableUpdates` to true in the `run.glick.moorai`
  domain, for example as a Forced key in the existing `MoorAI-config.mobileconfig`. The app reads
  `/Library/Managed Preferences/<user>/run.glick.moorai.plist`, then
  `/Library/Managed Preferences/run.glick.moorai.plist`. A managed `true` wins over the machine file.
- **Machine file:** `"updates": "off"` (or `"updates": false`) in `/etc/moorai/config.json` (macOS,
  Linux), owned by root and not group- or world-writable, not a symlink, in root-owned directories, or in
  `<ProgramData>\MoorAI\config.json` (Windows) with an ACL that lets only Administrators, SYSTEM or
  TrustedInstaller write it. A file that fails those checks is ignored. For example:
  `sudo install -d -m 0755 -o root /etc/moorai && echo '{"updates":"off"}' | sudo tee /etc/moorai/config.json && sudo chmod 0644 /etc/moorai/config.json`.
  If the file already exists (it also holds server mode and egress settings), add the key to it.

On Windows, `icacls` does not report a file's owner, so a file an ordinary user created and then limited
to an administrator-only ACL passes the check. Remove ordinary users' write access to
`<ProgramData>\MoorAI` at install time so they cannot create one.

**Signatures are unchanged.** Every update must still be signed with MoorAI's updater key (the
`pubkey` in `tauri.conf.json`). A self-hosted console can serve only builds that MoorAI signed. It
cannot sign its own builds and cannot downgrade the app.

The webview does not hold the `updater:default` permission, which would let it call the updater plugin
directly, past the endpoint choice and the off switch, and allow downgrades. Only the host's
`check_and_install_update` command runs updates.

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
