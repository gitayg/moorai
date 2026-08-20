# MoorAI — MDM fleet deployment (Jamf · Intune)

Zero-touch rollout of the **MoorAI agent** to a managed fleet: macOS via **Jamf Pro**,
Windows via **Microsoft Intune**. The MDM pushes the agent + the device→console binding;
**policy still comes from the console per-tenant at runtime** — nothing about detection
behavior is baked into these artifacts.

> **Scope.** This directory ships the *profiles, templates, deploy scripts, and this guide* —
> everything an admin needs to enroll a fleet. The one thing it cannot ship is a **code-signed /
> notarized build**, which needs your Apple Developer certificate and Windows Authenticode cert.
> Those steps are called out below as **[ADMIN PLACEHOLDER]**.

---

## 1. How MoorAI enrolls (the mechanism these artifacts automate)

MoorAI is **content-free and on-device**. Two things bind a device to your console:

| What | Where | Written by (interactive) | Written by (MDM) |
|---|---|---|---|
| **Enroll config** — `serverUrl`, `tenant`, `installToken` | `~/.curaiq/config.json` (per user)¹ | The desktop app's setup screen (`save_provision` in the Tauri host) when the user pastes an install token | The Jamf / Intune deploy script — **no token paste needed** |
| **Governance hooks** — PreToolUse entries for `Read`, `Bash`, `mcp__.*`, `Task` | `~/.claude/settings.json` (per user) | `node <MOORAI_HOME>/cli/moorai-hook.mjs install` | Same command, run by the deploy script as the user |

¹ Verified in source: `cli/config.mjs` reads `~/.curaiq/config.json` (legacy fallback
`~/.raiseme/config.json`), shape `{ serverUrl, tenant, installToken }`. On Windows the Rust host
resolves `~` to `%USERPROFILE%` (`src-tauri/src/platform.rs`), so the file is
`%USERPROFILE%\.curaiq\config.json`.

At runtime the agent pulls policy from:

```
GET  <serverUrl>/api/policy?tenant=<tenant>      header: X-Install-Token: <installToken>
POST <serverUrl>/api/alerts                       header: X-Install-Token: <installToken>   (content-free alerts)
```

Policy is cached at `~/.curaiq/hook-policy.json` for 60 s, and the agent **fails open** (allows)
when the console is unreachable — it is governance, not a sandbox. That is what makes a headless
MDM rollout safe: a device is useful the moment the agent is on disk, and becomes *governed* as
soon as the config binds it to a tenant.

### Enroll values (placeholders used throughout)

| Placeholder | Meaning | Example |
|---|---|---|
| `SERVER_URL` | MoorAI console base URL | `https://console.moorai.example.com` |
| `TENANT` | Tenant slug (selects console policy) | `acme-corp` |
| `INSTALL_TOKEN` | Per-tenant enroll token (`X-Install-Token`) | `it_live_xxxxxxxxxxxx` |
| `MOORAI_HOME` | Agent install dir | macOS `/usr/local/moorai` · Windows `C:\Program Files\MoorAI` |

> **Environment-variable alternative.** `cli/config.mjs` also honors `MoorAI_SERVER` and
> `MoorAI_TENANT` (note the exact mixed-case spelling — that is how the code reads them). There is
> **no** env override for the install token, so the reliable, complete enroll path is writing
> `config.json`, which is what both deploy scripts do. The install-time env vars `MOORAI_HOME`,
> `MOORAI_REF`, `MOORAI_NOHOOK` (all-caps) mirror `scripts/install.sh`.

> **Assumption (stated explicitly).** No single "MDM enroll" command exists in the repo today; the
> interactive path is the desktop app's token-paste screen (`save_provision`). These artifacts
> reproduce that same end state — the identical `~/.curaiq/config.json` file plus the hook
> registration — **non-interactively**. If your console later adds a dedicated enroll endpoint or a
> provisioning-profile format, swap the "write config.json" step for it; nothing else changes.

---

## 2. What gets deployed

Choose per platform. The **CLI agent** (governs any Claude Code terminal via hooks) is the minimum;
the **desktop app** (Tauri host that wraps the agent terminal) is optional on top.

| Component | macOS artifact | Windows artifact |
|---|---|---|
| CLI agent + hooks | `git` clone or prebuilt tarball into `MOORAI_HOME` | same |
| Desktop app *(optional)* | `MoorAI_<version>_universal.dmg` | `MoorAI_<version>_x64-setup.exe` (NSIS) |
| Enroll config | `~/.curaiq/config.json` (script) | `%USERPROFILE%\.curaiq\config.json` (script) |
| Managed values | `jamf/MoorAI-config.mobileconfig` | `intune/moorai-intune-config.json` |

---

## 3. macOS — Jamf Pro

### Files
- **`jamf/MoorAI-config.mobileconfig`** — configuration profile. Pre-seeds `ServerURL`, `Tenant`,
  `InstallToken` into the managed-preferences domain `run.glick.curaiq` (the app's bundle
  identifier). This is the MDM-locked *source of values*; the deploy script materializes them into
  `~/.curaiq/config.json`.
- **`jamf/moorai-jamf-deploy.sh`** — installs the agent, writes the per-user config, registers hooks.

### Steps

1. **[ADMIN PLACEHOLDER] Build a signed + notarized agent/app.** Follow `../../docs/SIGNING.md`:
   set `APPLE_SIGNING_IDENTITY`, `APPLE_ID`, `APPLE_PASSWORD`, `APPLE_TEAM_ID`, run
   `npx tauri build --bundles app,dmg`. Until certs are present, builds are ad-hoc signed and
   Gatekeeper warns on first open. Either notarize, or (interim) push a Jamf policy that removes the
   quarantine attribute (`xattr -dr com.apple.quarantine /Applications/MoorAI.app`). *Distributing
   the CLI-only agent via `git`/tarball needs no notarization — only the `.app`/`.dmg` does.*

2. **Upload the configuration profile.** Jamf Pro → **Computers → Configuration Profiles → Upload**
   → select `MoorAI-config.mobileconfig`. First replace every `REPLACE_WITH_*` value in the file
   (or set them blank and pass them as script params in step 4). Scope to your target smart group.

3. **(Optional) Package the desktop app.** Upload the notarized `.pkg`/`.dmg` to Jamf and deploy it
   with its own policy that runs **before** the script policy.

4. **Add the deploy script.** Jamf Pro → **Settings → Computer Management → Scripts → New** →
   paste `moorai-jamf-deploy.sh`. Define the parameter labels:

   | Jamf param | Label | Value |
   |---|---|---|
   | `$4` | Server URL | `SERVER_URL` *(or leave blank to use the profile)* |
   | `$5` | Tenant | `TENANT` |
   | `$6` | Install Token | `INSTALL_TOKEN` |
   | `$7` | MoorAI Home | `/usr/local/moorai` *(optional)* |
   | `$8` | Package URL | tarball URL *(optional; blank = git install)* |

   > If you set the values in the `.mobileconfig` (step 2), **leave $4–$6 blank** — the script reads
   > them back with `defaults read run.glick.curaiq …`. One source of truth, rotatable from Jamf.

5. **Create the policy.** Jamf Pro → **Policies → New**: trigger *Recurring Check-in* (+ *Enrollment
   Complete* for zero-touch), add the profile + the script, scope to the group. The script is
   idempotent — running it every check-in self-heals config drift and re-registers hooks for new
   users.

### Zero-touch flow (Jamf)
`Enrollment Complete` → profile installs (values land in `run.glick.curaiq`) → script installs the
agent, writes `~/.curaiq/config.json` for the console user, registers hooks → first Claude Code
tool call in any terminal pulls tenant policy from the console. No user interaction.

> **Per-user note.** Config + hooks live in `$HOME`. The script targets the **console user** by
> default (Jamf runs as root). To cover every local user or future logins, see the **ALL USERS**
> block at the bottom of `moorai-jamf-deploy.sh` (loop `/Users/*` + a login-triggered LaunchAgent).

---

## 4. Windows — Microsoft Intune (Win32 app)

### Files
- **`intune/Install-MoorAI.ps1`** — silent install + enroll (writes config, registers hooks).
- **`intune/Uninstall-MoorAI.ps1`** — silent uninstall (de-registers hooks, removes config + agent).
- **`intune/Detect-MoorAI.ps1`** — Intune detection rule (agent files **and** enrolled config present).
- **`intune/moorai-intune-config.json`** — reference values + the exact install/uninstall commands.

### Steps

1. **[ADMIN PLACEHOLDER] Sign the build.** The NSIS installer (`tauri.conf.json` →
   `bundle.targets` includes `nsis`, `installMode: currentUser`) should be **Authenticode-signed**
   with your code-signing certificate (`signtool sign /fd sha256 /tr <timestamp-url> /td sha256
   MoorAI_<version>_x64-setup.exe`) so SmartScreen doesn't warn. The Rust host reports signature
   validity via `Get-AuthenticodeSignature` (`src-tauri/src/platform.rs`). *The CLI-only agent
   (git/tarball) needs no signing.*

2. **[ADMIN PLACEHOLDER] Build the `.intunewin`.** Download the **Microsoft Win32 Content Prep
   Tool** (`IntuneWinAppUtil.exe`), put the four `intune/*.ps1` scripts (and, if deploying the
   desktop app, its `.exe`) in one source folder, then:

   ```
   IntuneWinAppUtil.exe -c <source-folder> -s Install-MoorAI.ps1 -o <output-folder>
   ```

   This produces `Install-MoorAI.intunewin`.

3. **Create the Win32 app.** Intune admin center → **Apps → Windows → Add → Windows app (Win32)** →
   upload the `.intunewin`. Fill in from `moorai-intune-config.json`:

   - **Install command** (replace the `REPLACE_WITH_*` values):
     ```
     powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Install-MoorAI.ps1 -ServerUrl "SERVER_URL" -Tenant "TENANT" -InstallToken "INSTALL_TOKEN"
     ```
   - **Uninstall command:**
     ```
     powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Uninstall-MoorAI.ps1
     ```
   - **Install behavior:** **User** *(recommended — config + hooks are per-user)*. If you must use
     **System**, pair with the logon task in the note below.

4. **Detection rule.** Rules format → **Use a custom detection script** → upload `Detect-MoorAI.ps1`.
   It exits 0 only when the agent files **and** an enrolled `config.json` (non-empty `serverUrl` +
   `tenant`) are present, so a half-finished install is retried.

5. **Assign.** Assign the app to a device/user group as **Required** for automatic install.

### Zero-touch flow (Intune)
Device enrolls → Win32 app installs in user context → `Install-MoorAI.ps1` clones/unpacks the
agent, writes `%USERPROFILE%\.curaiq\config.json`, registers hooks → detection script confirms →
first tool call pulls tenant policy. No interaction.

> **Per-user note (System-context installs).** In SYSTEM context `%USERPROFILE%` is the SYSTEM
> profile. `Install-MoorAI.ps1` resolves the logged-on user via `explorer.exe`'s owner and targets
> that profile. For devices with no interactive user at install time, deploy the agent in System
> context and add a **per-user logon scheduled task** that runs
> `node "C:\Program Files\MoorAI\cli\moorai-hook.mjs" install` and writes the config at first logon.

---

## 5. Verifying an enrolled device

```bash
# macOS
cat ~/.curaiq/config.json                       # serverUrl / tenant / installToken present
node /usr/local/moorai/cli/moorai-redteam.mjs   # prints "tenant: … · server: …" and policy status
grep -c moorai-hook ~/.claude/settings.json     # >= 1  → PreToolUse hooks registered
```

```powershell
# Windows
Get-Content "$env:USERPROFILE\.curaiq\config.json"
Select-String -Path "$env:USERPROFILE\.claude\settings.json" -Pattern moorai-hook
```

A successful pull shows the agent reaching `<SERVER_URL>/api/policy?tenant=<TENANT>` (visible in the
console's device list). Because the agent fails open, an unreachable console does **not** brick the
device — it simply runs on last-known/cached policy.

---

## 6. Signing & notarization — [ADMIN PLACEHOLDER] summary

Certificates are the one thing this directory can't provide. Detailed steps live in
`../../docs/SIGNING.md` (macOS); the Windows equivalent is Authenticode `signtool`.

| Platform | Needs | Result |
|---|---|---|
| macOS `.app`/`.dmg` | Apple **Developer ID Application** cert + notarization (`APPLE_*` env) | Gatekeeper-clean open |
| Windows `.exe` | **Authenticode** code-signing cert (`signtool sign …`) | No SmartScreen warning |
| CLI agent (git/tarball) | *nothing* | Ships as-is |

Until certs exist, deploy the **CLI-only agent** fleet-wide (fully functional, no signing) and treat
the desktop app as an opt-in follow-up once the build is notarized/signed.

---

## 7. Uninstall / offboarding

- **macOS:** run `node <MOORAI_HOME>/cli/moorai-hook.mjs uninstall` (removes only MoorAI's hook
  entries), then delete `~/.curaiq` and `MOORAI_HOME`. Remove the Jamf profile to unbind values.
- **Windows:** the Intune **Uninstall** action runs `Uninstall-MoorAI.ps1` (de-registers hooks,
  removes `~/.curaiq` and `MOORAI_HOME`).

---

## File tree

```
packaging/mdm/
├── README.md                         # this guide
├── jamf/
│   ├── MoorAI-config.mobileconfig    # macOS configuration profile (managed values)
│   └── moorai-jamf-deploy.sh         # install + enroll + hook registration (bash)
└── intune/
    ├── Install-MoorAI.ps1            # silent install + enroll (PowerShell)
    ├── Uninstall-MoorAI.ps1          # silent uninstall
    ├── Detect-MoorAI.ps1             # Win32 detection rule
    └── moorai-intune-config.json     # reference values + install/uninstall commands
```
