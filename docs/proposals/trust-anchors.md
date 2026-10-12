# Design: moving MoorAI's trust anchors out of the agent's reach

**Summary**

1. MoorAI and the agent it guards run as the same OS user. Anything only that user protects is therefore agent-controlled, and that includes Keychain items readable via `security`, DPAPI, Credential Manager and the Secret Service.
2. The code contradicts the brief in four places (section 1.3). (a) `console.json` lives in `MoorAI Host/`, not in `app_data_dir`. (b) On a laptop the hook never reads `/etc/moorai/config.json`; it does so only in server mode. (c) The host's credentialed calls ignore an admin-provisioned console. (d) The install token is per tenant, so console-side heartbeats can be forged today.
3. Deleting one line (`installToken`) from `~/.moorai/config.json` switches a fail-open device to coach mode with no alerts. That is goal (e), achieved silently.
4. On Windows the hook builds its anchor paths from `%ProgramData%`, which is user-settable. With the icacls owner gap, an agent may be able to forge every "root-owned" anchor. This is unverified on a real Windows box.
5. **Phase 1 (M–L):** an admin source wins on every component, and a managed device can never drop to coach mode. Cache freshness comes from the signed `iat`, not the file's mtime. Hook command and environment are hardened. The console adds new rules: alerts missing per session, device gone quiet, update lag.
6. **Phase 2 (XL):** a privileged helper per OS (LaunchDaemon via SMAppService, Windows service, systemd unit). It holds the binding, the secret token, a per-device signing key, the policy cache, back-off and the alert queue. The hook reaches it over a peer-checked local IPC endpoint.
7. In phase 2 the helper sees agent processes independently and reports "agent active, hook silent" with a device signature the agent cannot forge. The console expects a signed beat every 5 minutes and uses boot-id and uptime to tell "helper stopped" from "laptop asleep".
8. **Phase 3 (M–L):** the helper keeps a hash-chained event log whose head is anchored in every signed beat, so the console detects deletion, rewriting or forking. Unmanaged devices get only a weak version of this, and the doc says so.
9. Consumer tier: an enrolled but unmanaged device gets tamper evidence that a careful agent can defeat. macOS can do better without admin, using a signed per-user agent and the data protection keychain. Windows and Linux cannot.
10. Residual risks after all phases: an agent with sudo or admin, the user disabling MoorAI, agents MoorAI does not recognise, hosts without managed hook settings, and detection latency.

---

## 1. Problem statement

MoorAI's hook (`cli/moorai-hook.mjs`), its MCP guard and gateway, the Agent SDK and the Tauri host all run as the logged-in user. So does the AI agent. Four rounds of review keep finding another user-scope file that steers a security decision. Fixing these one at a time does not converge, because the trust boundary is in the wrong place. The code already admits this. `docs/CAPABILITY_SPEC.md:327-328` says "the hook runs as the user, so nothing under `~/` is a trust boundary". `docs/CAPABILITY_SPEC.md:298-301` says that touching the cache "skips the fetch on every call" and that rewriting `serverUrl` "silences the console for the hook indefinitely".

### 1.1 Trust inputs the agent can write (found in code)

| # | Input (file:line) | What it steers | Current mitigation | Gap |
|---|---|---|---|---|
| 1 | `~/.moorai/config.json` `serverUrl`/`tenant`/`installToken`, read by `cli/config.mjs:20-24` | Hook policy fetch origin (`cli/hook-core.mjs:2015-2017`); every alert post (`cli/moorai-hook.mjs:623`, `663`); posture heartbeat (`:1048`); MCP guard (`mcp-proxy/moorai-mcp-guard.mjs:102,124`); gateway (`mcp-gateway/report.mjs:21,47`) | Policy signature with anchor or pin refuses an unsigned body from a repointed URL (`hook-core.mjs:2051-2055`) | Alerts, heartbeats and the token go to whatever URL the file names. Suppression and redirect are silent. |
| 2 | Legacy `~/.curaiq/config.json` and `~/.raiseme/config.json`: `cli/config.mjs:20`; host `src-tauri/src/platform.rs:30-39` | Same as #1 when the primary file is missing or does not parse | None | Corrupt the primary and plant a legacy file |
| 3 | Absence of `installToken` → `COACH = !enforcementAllowed(...)` (`cli/moorai-hook.mjs:2165`, `data/enforcement.js:19-26`) | Whether anything is blocked, and whether anything is posted | A fail-closed posture or server mode counts as "managed" | A fail-open enrolled device drops to coach mode and goes silent. This is goal (e). |
| 4 | `MoorAI_SERVER`/`MoorAI_TENANT` env (`cli/config.mjs:14-15`) | Fallback console when no config file exists | Not passed through `trustedEnv` | Low impact: unenrolled devices only |
| 5 | Settings-file `env` blocks: `NODE_OPTIONS`, `PATH`, `ProgramData` (`cli/server-mode.mjs` `isGuarded` = `/^(MOORAI_\|MoorAI_)/`); hook command is `node "<path>"`, resolved through PATH (`cli/moorai-hook.mjs:172`) | Code that runs inside the hook (`--require`), which `node` runs at all, and anchor paths (#6) | `MOORAI_*` set by a settings file is refused and reported (`server-mode.mjs:121-149`) | `NODE_OPTIONS` and PATH shims can take over the hook. Whether Claude Code applies settings `env` to hook processes is as the code comments quote the docs; I did not re-verify it. |
| 6 | `%ProgramData%` taken from **env** in the hook's Windows anchor paths: `hook-core.mjs:377,1716,1741,1753,1851`, `cli/exceptions.mjs:38`, `cli/server-mode.mjs` `systemConfigPath` | `policy.pub`, `breakglass.pub`, posture latch, HWM, system LKG, exceptions, system config | `readRootOwned` checks the DACL with icacls (`hook-core.mjs:1662-1685`). The Rust host reads ProgramData from HKLM instead (`admin_config.rs:56-76`). | The path is user-chosen, and the icacls owner gap (`hook-core.mjs:1632-1660`) lets the file's owner strip its ACL to look admin-only. **Unverified on Windows.** If it holds, every "hard" Windows anchor in the hook is forgeable. |
| 7 | Policy cache `~/.moorai/hook-policy.json` (`hook-core.mjs:1691`; freshness check `:1996-2002`) | Skips the fetch while mtime is under 60 s | Signature plus rollback mark (`:1972-1990`); future mtime rejected | `touch` keeps an old but validly signed policy forever (goal d) |
| 8 | Pin and its HWM: `policy-pin.json` in `~/.moorai` and `~/.config/moorai` (`hook-core.mjs:1726-1728`), breadcrumb (`:1762`) | Which keys verify; the rollback mark is `pin.iat` (`:1972`) | Two copies, breadcrumb, pin-absence alert (`:1963-1968`); root `policy-hwm.json` when shipped | Rewinding `iat` in both copies lets an older signed policy replay (`CAPABILITY_SPEC.md:320-327`) |
| 9 | LKG copies (`hook-core.mjs:1749-1751`) | Policy used when fresh and cache both fail | Re-verified against anchor or pin and mark | Same rewind as #8 |
| 10 | Posture copies `~/.moorai/posture`, `~/.config/moorai/posture`, `~/.curaiq/offline-posture` (`hook-core.mjs:1700-1702`) | Fail-open vs fail-closed when no policy | Ratchet: strongest value wins; a downgrade is alerted (`:670-689`) | Only `/etc/moorai/offline-posture` is hard |
| 11 | `~/.moorai/hook-console-backoff.json` (`cli/console-backoff.mjs:22`) | Skips the policy fetch | Delay only: 1 call in 8 still fetches; future or malformed values ignored | Delays a refresh by about 8 calls |
| 12 | Deferred alert jobs `~/.moorai/alertpost-*.json` (`cli/moorai-hook.mjs:643-666`) | Alerts queued while the console was unreachable | 0600, worker detached | Deleting a job before the worker reads it drops alerts silently (goal b). Planted jobs are posted with the real token. The worker re-reads the config, so #1 also redirects them. |
| 13 | `~/.moorai/posture-beat-<host>.json` (`cli/moorai-hook.mjs:1020-1037`) | Whether today's heartbeat is sent | Console "bypass" sweep (`RAISEME-server/server/coverage.js:17-23,312-335`) | Writing `{day: today}` suppresses the beat. The sweep only notices if an independent activity source exists (desktop-app prompts or activity beacon). CLI-only devices just go quiet. |
| 14 | Session ledger `~/.moorai/<ledger>` (`cli/session-ledger.mjs:25`) | Session-summary counts posted at Stop (`moorai-hook.mjs:1957-1975`) | None | Rewritable, so the counts are claims |
| 15 | Hook code under `~/.moorai` for consumer installs (`scripts/install.sh:14`); hook registration in `~/.claude/settings.json` | Whether the hook exists and what it does | MDM installs put the code under root-owned `/usr/local/moorai` (`packaging/mdm/jamf/moorai-jamf-deploy.sh:39,121`); posture flags a missing hook or `disableAllHooks` | Those posture flags are reported by the hook's own heartbeat, which stops when the hook is removed |
| 16 | Host binding `console.json` in `~/Library/Application Support/MoorAI Host/` (macOS), `%LOCALAPPDATA%\MoorAI Host` (Windows), `$XDG_DATA_HOME/MoorAI Host` (Linux): `console_binding.rs:23-33,61-65` | Credentialed host calls (`console_http.rs:51-57`), the tool allow-list (`lib.rs:395`), enrolment base and update source via `source:"enrolment"` (`console_binding.rs:105-109`, `update_source.rs:49-52`) | Written only at enrolment; Seatbelt denies writes for agents the app launches with isolation on (`platform.rs:251-261`); MXC denies on Windows (`mxc.rs:52`) | An agent not launched by the app writes `{"origin":"https://evil","source":"enrolment"}`. That redirects the token and, without an admin console, the update source. |
| 17 | Admin console vs `console.json` | `console_binding::resolve(dir,cfg)` never consults `admin_config::admin()` | Admin console wins only for updates and uncredentialed calls | Gap #16 is still open on managed devices |
| 18 | Webview localStorage `raiseme.server`/`raiseme.installToken`/`raiseme.tenant` (`src/api.js:20,27,88,249-251`; `src/content-hash.js:98`) | Plain-browser console base; content-hash key | Ignored inside the host (`api.js:86-88`) | The token is mirrored there in readable form |
| 19 | `~/.moorai/kill-session` sentinel (`lib.rs:827-834`, polled every 600 ms) | Kill-session delivery | 60 s staleness check | A background loop can delete it (kill suppressed) or plant it (DoS) |
| 20 | `app_data_dir/audit.jsonl` (`lib.rs:367-377`), on-device chained logs (`cli/record-chain.mjs`) | Local evidence | The chain is anchored only if an OTel/SIEM stream exists (`record-chain.mjs:13-17`) | Deletable |
| 21 | `~/.moorai/agent-sandbox.sb` (`platform.rs:288-294`) | Seatbelt profile, written and then used | None | Minor TOCTOU |
| — | Already outside the agent's reach | `/etc/moorai/*` via `readRootOwned`/`read_owned_under`; managed prefs; local exceptions read only from the root store (`exceptions.mjs:11-27`); ed25519 policy signature | — | — |

### 1.2 What already exists on the console (`RAISEME-server/server`)
- **Daily heartbeat and posture.** `POST /api/agent-posture` writes the `agent_heartbeats` and `agent_posture` tables (`coverage.js:155-165`). Findings: bypass (activity with no beat), weakened setting, hook removed or stale, untested version, no containment. Grace is 120 min (`coverage.js:132`).
- **Session summaries.** Integer counts stored in `alerts.session_summary` (`session-summary.js:6`), used as denominators by `agent-metrics.js`. **Nothing compares them with the alerts actually received.**
- **Multi-device identity** (`multi-device.js`) and MCP proxy-vs-hook cross-check (`mcp-usage.js`).
- **No device-level "went quiet" detection.** The sweep needs activity evidence.
- **Auth is a per-tenant install token.** `server.js:357-362` maps token to tenant; `installations` is keyed by token (`db.js:149-155`); `packaging/mdm/README.md:47` calls it a "Per-tenant enroll token". User and device in the request body are self-asserted. **Anyone holding the token, including the agent that reads `~/.moorai/config.json`, can forge heartbeats, posture and alerts for any device.** Console-side detection is only as strong as the device credential behind it.
- The console signs each policy response with `iat = now` (`policy-sign.js:74-79`). Phase 1 relies on this.

### 1.3 Where the code contradicts the brief
1. **`console.json` location.** It is not in `app_data_dir` (`~/Library/Application Support/run.glick.moorai/`). It is in `host_dir()` = `~/Library/Application Support/MoorAI Host/console.json` (`console_binding.rs:23-33`). `app_data_dir` holds only `audit.jsonl` (`lib.rs:369`).
2. **"Admin file already supported."** True for the Tauri host's provisioned console and update switch (`admin_config.rs`). **False for the hook on a laptop:** `cli/config.mjs:10-24` reads `/etc/moorai/config.json` only when `serverMode()` is active (`server-mode.mjs:229-238`). False too for the host's credentialed path (#17). The MDM scripts write the binding to `~/.moorai/config.json`, not `/etc` (`packaging/mdm/README.md:21,74`). The Jamf profile already carries `Tenant` and `InstallToken` in managed prefs, but `admin_config.rs` reads only `ServerURL` and `DisableUpdates`.
3. **"The ONLY hard guarantee"** (`hook-core.mjs:791`) refers to `/etc/moorai/policy.pub` specifically. The root posture latch and `policy-hwm.json` are described separately as hard where present.
4. **Policy cache path.** `~/.moorai/hook-policy.json` is correct (`hook-core.mjs:1691`). Several comments still say `~/.curaiq/hook-policy.json`; they are stale.
5. **The Windows "root-owned" anchors in the hook are weaker than the brief assumes** (#6).

## 2. Threat model

**Adversary.** A prompt-injected or misaligned agent running as the logged-in user. It can read, write and delete anything the user can. It can start detached processes, edit `~/.claude/settings*.json` and project settings, set env for later hooks, kill same-user processes, bind same-user sockets and pipes, and read every secret the user can, including the tenant install token. It **cannot**, without escalation: write root- or SYSTEM-owned paths; stop system daemons or services; attach to hardened-runtime processes; enter the keychain password or answer a UAC prompt on the secure desktop; or change the system clock or routing.

**Escalation is out of scope but named.** NOPASSWD sudo, a cached sudo ticket shared with the agent's TTY, UAC auto-elevation, or a password the agent finds on disk all give the agent root, and nothing local survives that.

**Assets and goals.** These are the goals from the brief: (a) where credentials, alerts and policy fetches go; (b) alert delivery; (c) the update channel; (d) policy freshness; (e) enforcement being on.

**"Silent".** No signal reaches the console from a source the agent cannot forge or erase. Two consequences follow. A signal posted with the tenant token is forgeable. A signal queued in user space is erasable.

**Tiers.**
- **T0, unenrolled consumer.** Coach mode only. There is no console to report to, so goal 1 does not apply. Stated, not fixed.
- **T1, enrolled, unmanaged.** No admin rights. Tamper evidence holds against a naive agent only. macOS can reach T1+ (§3.1).
- **T2, managed.** MDM or admin install. Root-owned config and helper. Prevention for (a)(c)(d), signed detection for (b)(e).

## 3. Options analysis

### 3.1 macOS Keychain
**File-based login keychain (what `security` uses).** Items carry per-item ACLs. Reading the secret from a process outside the ACL, for example `security find-generic-password -s X -w`, raises a SecurityAgent dialog that asks for the login password or Touch ID. "Always Allow" adds `/usr/bin/security` itself to the ACL, so every later script gets the item (scriptingosx, see Sources). Without `-w`/`-g`, attributes print with no prompt; that is my understanding and I have not verified it on macOS 26/27. **Not verified:** whether deleting an item outside the ACL prompts. Assume the agent can delete it, or delete it and re-create one with the same name. A **Node hook cannot be on the ACL in any useful way.** The ACL would have to trust the `node` binary, which the agent runs too.

**Data protection keychain (`kSecUseDataProtectionKeychain`).** Access is controlled by keychain access groups and entitlements, not prompts. Per Apple DTS (forums 807782, 836816, 719219):
- `security` has no access to it;
- the entitlements are restricted and must be authorised by a provisioning profile;
- a command-line tool cannot embed a profile, so it needs an app-like wrapper;
- it is available only in a user login context, so **not from a launchd daemon**.

A process without the group cannot read, change or delete the item. Note that current builds are ad hoc signed (`docs/SIGNING.md:5`). Developer ID signing, hardened runtime and a Developer ID provisioning profile come first.
- **Protects:** confidentiality and integrity of the binding, token, device key, counters and chain head against a same-user agent. This holds on T1 with no admin, only for code inside the signed wrapper.
- **Does not protect:** availability (the agent kills the agent process and removes its LaunchAgent plist), the hook's honesty, Windows or Linux.
- **Install:** a signed app; a per-user LaunchAgent (KeepAlive) embedded in the bundle.
- **Effort:** L.
- **UX:** none beyond the Login Items entry. **Verify on hardware** that a LaunchAgent counts as a "user login context".

### 3.2 Windows DPAPI and Credential Manager
Stated plainly: `CryptProtectData` with user scope can be undone by any process running as the same user via `CryptUnprotectData`. Optional entropy only obscures. `CredRead` returns Credential Manager secrets to any same-user process. **Neither isolates anything from the agent.** Also, MSIX full-trust app data is user-accessible. Windows has no T1+ equivalent of §3.1.

The real option is a **service** running as LocalSystem or a virtual account (`NT SERVICE\MoorAI`):
- state under `%ProgramData%\MoorAI\state`, with the ACL SYSTEM plus service SID only, and the path taken from HKLM as `admin_config.rs` already does;
- a named pipe `\\.\pipe\MoorAI.Hook` created with `FILE_FLAG_FIRST_PIPE_INSTANCE` and a DACL granting Authenticated Users connect;
- the client checks `GetNamedPipeServerProcessId`, then the server process token's SID, which defeats pipe squatting;
- the service identifies the caller with `GetNamedPipeClientProcessId` or `ImpersonateNamedPipeClient`;
- stopping it needs `SERVICE_STOP`, which the default DACL gives to Administrators and SYSTEM. Set it explicitly with `SetServiceObjectSecurity`;
- recovery actions restart it.

A non-elevated agent can't approve UAC on the secure desktop (`PromptOnSecureDesktop=1`). The secret can additionally be a CNG key in machine storage, optionally TPM-backed via the Microsoft Platform Crypto Provider.

### 3.3 Privileged helper daemon (all OSes)
- **macOS:** `SMAppService.daemon(plistName:)` (macOS 13+) with the plist at `Contents/Library/LaunchDaemons`. The user must approve it in Login Items, which asks for admin authentication. MDM can pre-approve it with the Managed Login Items payload (`com.apple.servicemanagement`). The older alternative is a pkg-installed `/Library/LaunchDaemons` plist. Run as root or a dedicated `_moorai` user (`UserName`). State lives in `/Library/Application Support/MoorAI/state` (0700). The socket is `/var/run/moorai/hook.sock` in a root-owned directory; read the peer with `LOCAL_PEERCRED`/`LOCAL_PEERPID`. **It cannot use the data protection keychain** (§3.1); use root-only files, or the System keychain.
- **Linux:** a systemd system unit with `User=moorai` (or `DynamicUser=`), `StateDirectory=moorai` (`/var/lib/moorai` 0700), a socket unit `ListenStream=/run/moorai/hook.sock`, `SocketMode=0666`, and `SO_PEERCRED`. Stopping it needs polkit `manage-units`; the default is `auth_admin`, but distros vary (**verify per distro**).
- **Windows:** §3.2.

**What peer checks give you.** They tell you the caller's uid and pid. They do **not** tell the hook apart from the agent, because both are `node` running as the same user. So the helper's value is not trusting the hook. It is: (1) holding state and secrets the agent can't touch; (2) being the only outbound path to the console, with its own device key; (3) observing independently. As root it can enumerate processes (sysctl/`proc_pidpath`, `/proc`, Toolhelp), so it sees `claude`/`codex`/`cursor`/`gemini`/`copilot` processes and compares them with the hook IPC traffic it received. The hook verifies the helper in turn: the socket's peer uid must be 0 or `_moorai`, or the pipe server SID must be SYSTEM, and the path is never configurable from env.
- **Protects:** (a)(c)(d) fully on T2; (b) once the helper acks; (e) as signed detection.
- **Does not protect:** a forged hook submitting lies. Mitigation: Claude Code managed settings with `allowManagedHooksOnly` pointing at root-owned code (`packaging/mdm/README.md:77-80`), plus the helper checking the client's image, script path and `NODE_OPTIONS` (best effort).
- **Install:** admin or MDM.
- **Effort:** XL.
- **UX:** one approval on unmanaged Macs, none under MDM.

### 3.4 Tamper-evident logs
`cli/record-chain.mjs` already builds `chash = sha256(prev|seq|rhash)`, but it is anchored only via OTel. A same-user chain plus a same-user queue fails against an agent that deletes un-sent records and rewinds the head: the console never saw those records. Without a helper or a keychain-held head, this catches only naive deletion and deletion of records already anchored. With the helper, the head lives in root-owned state (or the data protection keychain on T1+ macOS) and goes into every signed beat. The console stores the last head and seq. A gap, a fork or a regression is a High finding.

### 3.5 Console-side detection
- **Cheap now, forgeable with the tenant token:**
  - **Session reconciliation:** `summary.deny + ask` compared with the alerts received under the same session key.
  - **Device gone quiet:** a device with ≥ k days of beats goes silent for > N days while other channels from it (device-report, MCP proxy, alerts) continue, or simply stops.
  - **Update lag:** reported `appVersion` or hook version stays behind the latest for > N days.
  - **Policy age:** the hook reports the `policySig.iat` it is enforcing.
- **Strong only with per-device keys (phase 2):** an expected signed beat every 5 minutes, carrying boot id, uptime, seq, chain head, hook-call and agent-process counters, policy age and versions.

### 3.6 Admin-file-only binding
This is mostly built: `read_owned_under` (O_NOFOLLOW, ownership of every ancestor directory) on macOS and Linux; HKLM paths plus icacls and a share lock on Windows. What's missing: the hook honouring the admin file on laptops; the host's credentialed path; managed `Tenant`/`InstallToken`; MDM scripts writing the root file; and "admin present ⇒ user binding refused and reported".
- **Protects:** (a)(c) on T2 at once.
- **Does not protect:** token confidentiality, because a 0644 file is readable by the agent.
- **Effort:** M. **UX:** none.

### 3.7 (Considered) Contain the agent
Seatbelt (`platform.rs:245-261`) and MXC already deny the agent writes to `MoorAI Host`. Extending the deny list to `~/.moorai`, `~/.config/moorai` and `~/.claude/settings*.json` would close most of §1.1. But it only covers agents the desktop app launches, the hook inherits the sandbox and so can't write its own state, and `sandbox-exec` is deprecated. It is a complement to phase 2, not the answer.

## 4. Recommended architecture

**Principle.** Every trust decision reads from exactly one place. On T2 that is root/SYSTEM-owned state, through the helper. On T1 it is user state plus console reconciliation, labelled "evidence, not guarantee". When an admin source exists, user-scope values are **refused and reported**, never merged in.

### Phase 1: admin source wins, freshness from the signature, console reconciliation (M–L overall)

**Status: 1A–1D built in agent v1.13.0; 1E is the console's (RAISEME-server v0.83.0).** What was built,
and how it differs from the plan below:
- **1A.** `cli/config.mjs` `resolveBinding()` reads the root-owned machine config first on every component that
  uses `loadConfig()` (hook, `claude -p` guard, MCP guard, gateway, doctor). **Changed from the plan:** the machine
  file carries only `serverUrl` and `tenant`; an `installToken` in it is ignored, because the file is readable by
  every local account, and the token stays in the enrolled user's own 0600 `config.json`. A user value that
  disagrees with the machine `serverUrl` or `tenant` is refused and reported (`BINDING_REFUSED`, key names). A
  managed device never coaches (`data/enforcement.js` counts `config.managed`); without a token it enforces, writes
  `binding:no-token` to the local action audit and still takes alert `seq` numbers, so the gap shows on the console.
  Windows anchor paths come from HKLM through `cli/machine-dir.mjs` (`reg.exe` and `icacls.exe` by absolute path;
  the system root is the fixed `C:\Windows`, `%SystemRoot%` only when that has no `reg.exe`). Host: `resolve()`
  takes `&Admin`; the admin console is the only credentialed origin for `console_fetch`, `tool_allowed` and
  `identity`, `console.json` is not read when it is set, and `save_provision` refuses to move a managed device.
  `admin_config.rs` reads managed `Tenant`/`InstallToken` and machine-file `tenant` (not `installToken`). The
  Jamf and Intune scripts write the machine config (no token) and keep writing the token to the user's file;
  there is no Linux script, the MDM README carries the commands. The scripts do not fetch `policy.pub` or
  `policy-hwm.json` (not built).
- **1B.** As planned: `policyFreshByIat`, default 15 min, `policyMaxAgeMinutes` in the signed policy (1–10080).
  `POLICY_STALE` carries an integer `ageMinutes`, and fires whenever the enforced policy is older than the maximum
  age (a failed or skipped refetch, or a fresh answer with an old `iat`). `policyIat` is ISO 8601 (`toISOString`).
  The MCP guard and gateway share the loader, so they refetch the same way, but they do not raise `POLICY_STALE`.
- **1C.** As planned. The refusal alert is the existing "Policy: environment set by a settings file refused" with a
  new `refusedEnv` list (PATH alone is High); the posture flag is `hookEnvOverride`, which RAISEME-server drops on
  ingest until it adds the name. Adapter hooks (Codex, Cursor, Gemini, Copilot) also register node by absolute
  path; the Claude Code plugin's `hooks/hooks.json` cannot and still says `node`.
- **1D.** `seq`/`chainHead` come from one `record-chain` chain over the hook's alerts (`cli/alert-seq.mjs`, a lock
  file keeps parallel hooks from sharing a number). Only the hook sends them; the MCP guard, gateway, SDK and the
  desktop app do not. Every hook alert also carries `appVersion` (MoorAI's package version).

**Verified** (each test failed on v1.12.1 or under a deliberate revert of its fix line, and passes now):
`test/trust-anchor-binding.test.mjs` (system good + user evil: the evil listener gets 0 requests; managed with no
token: reverse shell denied, not coached), `test/policy-freshness.test.mjs` (signed cache with `iat` 2 h old and a
touched mtime: `GET /api/policy` happens; failed refetch: `POLICY_STALE`, `policyIat` on every alert),
`test/hook-env-hardening.test.mjs` (absolute node in `hookEntry`; settings-file `NODE_OPTIONS` raises the refusal
alert; HKLM ProgramData with a hostile env), `test/alert-evidence.test.mjs` (contiguous `seq` across direct and
deferred posts; `alertsEmitted` equals the session's alerts received), `test/mdm-machine-config.test.mjs`, and the
Rust test `a_planted_enrolment_record_does_not_move_the_token_off_the_admin_console`. **Not verified:** the
Windows ProgramData test has not run on Windows (it runs in `windows-js`), nothing was run on a real Windows box,
and the MDM scripts have not run on a managed Mac or an Intune device.

**1A. One binding resolver, admin first, on every component (M).**
- `cli/config.mjs` `loadConfig()`: on laptops too, call `readRootOwned(systemConfigPath())` first. If it carries `serverUrl` (and optionally `tenant` and `installToken`), those values win, and `~/.moorai`, `~/.curaiq` and `~/.raiseme` `serverUrl`/`installToken` are ignored. Return `{managed:true, sources}`. A disagreeing user file raises a content-free tamper alert, "user binding refused (admin binding present)".
- Fix the Windows path: take `ProgramData` from HKLM in Node, via `reg query` cached per process, or a host-written root file. Never from `process.env`. This applies to `hook-core.mjs:377,1716,1741,1753,1851`, `exceptions.mjs:38` and `server-mode.mjs systemConfigPath`.
- `data/enforcement.js` / `moorai-hook.mjs:2165`: `managed` also includes "admin binding present". A managed device never drops to coach mode, whatever the user file says.
- `src-tauri/src/console_binding.rs` `resolve()`: take `&Admin`. If `admin.console` is set, it is the credentialed origin, and `console.json` is ignored (with a warning if it differs). `console_http::target`, `lib.rs` `tool_allowed`/`identity`/`save_provision` all use it. `save_provision` on a managed device refuses to move the console.
- `admin_config.rs`: read managed `Tenant` and `InstallToken`, and machine-file `tenant`/`installToken`. When present, `read_config()` consumers use them in place of the user file.
- `packaging/mdm/jamf/moorai-jamf-deploy.sh`, `intune/Install-MoorAI.ps1`: write `/etc/moorai/config.json` (root:wheel 0644) or `%ProgramData%\MoorAI\config.json` (hardened ACL, `/setowner` Administrators). Fetch and install `policy.pub` and `policy-hwm.json` at deploy time. Stop writing the token to the user file.
- **Honest limit:** the token stays readable, in a 0644 file, until phase 2.

**1B. Freshness from the signed `iat` (S).** At `hook-core.mjs:1996-2002`, the cache short-circuits only if mtime is under 60 s **and** `now - policySig.iat < POLICY_MAX_AGE`, with a default of 15 min, configurable only through the signed policy. Past that, fetch. If the fetch fails, enforce, then raise `policy:stale` with `ageMinutes`. Every alert carries `policyIat`. The console flags devices whose `policyIat` lags.

**1C. Hook command and environment (S).**
- `hookEntry` writes the absolute `process.execPath` in place of `node`.
- `isGuarded`, `refusedTrustEnv` and the agent-posture flags cover `NODE_OPTIONS`, `NODE_PATH`, `PATH` and `ProgramData` set by a settings file. Report them.
- `moorai-doctor` warns when the hook code is user-writable (consumer install in `~/.moorai`).

**1D. Naive-deletion evidence on T1 (S).** Each alert carries a per-device `seq` from a user-scope counter, plus the record-chain head. The session summary adds `alertsEmitted`/`alertsDeferred`. This is labelled as catching only an agent that doesn't also rewind counters.

**1E. Console rules (M), in RAISEME-server:**
- `session-reconcile`: summary counts compared with alerts received for that session key → "Alerts missing for session".
- `device-quiet`: per device, from `agent_heartbeats` and `devices.last_report`.
- `seq-gap` / `seq-regress` per device.
- `update-lag`: device `appVersion` or hook version compared with the latest released.
- `policy-age`: from `policyIat`.
- `binding-refused`: surfaces the 1A tamper alerts.

All Info/Low/Medium, tagged "evidence (token-authenticated)".

**Phase 1 tests (each fails on today's code):**
- Pure `resolveBinding({system, user, env})` test: system `good`, user `evil` → `good`; fake console at `evil` receives 0 requests in a spawned-hook e2e. The system read is injected the same way `server-mode.mjs` injects `read`; no production env override.
- Managed device whose user config has no token: a reverse-shell `Bash` call → `deny`, not a coach allow. Today `COACH=true`.
- Rust: planted `console.json` `{origin: evil, source: enrolment}` plus `Admin{console: good}` → `console_fetch` credentialed goes to `good`, and the `evil` listener sees nothing. Pattern: `console_binding.rs:197-209`. Today it goes to `evil`.
- Validly signed cache with `iat = now-2h` and freshly touched mtime → the fake console sees `GET /api/policy`. Today: 0 requests.
- `ProgramData` env pointing at a scratch dir with a forged `policy.pub` → ignored. Windows CI only.
- `hookEntry` produces an absolute node path; a settings file with `NODE_OPTIONS` → refusal alert.
- Console: summary `deny=3` with 1 Blocked alert → finding; 7 days of beats then 4 days of silence → `device-quiet`; seq 10,11,14 → `seq-gap`.

### Phase 2: the privileged helper, `moorai-guardd` (XL)

**Component.** A new Rust crate (workspace member next to `src-tauri`). It reuses `admin_config.rs`, `console_binding::normalize_origin`, `console_http` routing and the policy verifier, ported or shared from `hook-core.mjs`.

**It holds:**
- the binding, from the admin file only on T2;
- the install token, moved to a root-only `/etc/moorai/secret.json` (0600) or `%ProgramData%\MoorAI\secret.json` (SYSTEM-only), delivered by MDM;
- a **per-device ed25519 key**, generated at first start;
- pin, HWM, policy cache and LKG, posture, back-off, alert queue, chain.

**It does:**
- fetches and verifies policy every 60 s while hooks are active, else every 10 min;
- delivers alerts with retry, signing each batch with `X-Device-Key`/`X-Device-Sig` over `(body, ts, nonce)`;
- posts a signed beat every 5 min: boot id, uptime, seq, chain head, hook calls per host, agent processes seen per host, policy `iat`, hook/app/helper versions;
- runs process observation and raises "agent active, hook silent" locally after 2 minutes;
- reports update lag. Optionally it updates root-owned hook code from the console's signed channel.

**IPC** (length-prefixed JSON, 50 ms connect budget). Ops:
- `hello`: helper version and identity;
- `policy`: the signed bytes plus `iat`, `fetchedAt`, `source`;
- `submit`: alerts, returns `seq` ack. The hook awaits the ack before exiting, so deletion is impossible once acked;
- `call`: event, host, session hash, counts the invocation;
- `kill`: replaces the sentinel file.

The hook still verifies policy signatures. If the helper is unreachable on a device whose admin file says `"helper":"required"`, the hook enforces with the posture default and stamps `helperUnreachable`. The console sees the beat gap anyway.

**Console (M–L).**
- `POST /api/devices/register`: public key, device pseudonym, platform. Authenticated by the root-only token or a one-time MDM secret. A changed key for an existing device → High "device key changed".
- Table `device_keys(tenant, device, key, registered_at, last_beat_at, boot_id, uptime, seq, chain_head)`.
- Sweep findings:
  - beat missing while the next beat shows the same boot id and continuous uptime → High "helper stopped while device up";
  - beat missing otherwise → Info "offline";
  - helper "agent active, hook silent" → High;
  - an unsigned alert claiming a key-holding device → Medium "token-only alert from helper-managed device".
- Tenant setting `requireDeviceKeys`: tenant-token-only alerts and heartbeats are then marked untrusted.

**Per OS.**
- **macOS:** SMAppService daemon in the app bundle, pre-approved via the MDM Managed Login Items payload. A pkg-installed LaunchDaemon for CLI-only fleets.
- **T1+ macOS:** the same binary as a per-user LaunchAgent in the signed wrapper, with state in the data protection keychain. No root. Availability depends on the user, but state integrity holds.
- **Windows:** a service installed by the NSIS/Intune script.
- **Linux:** systemd units, packaged as deb/rpm, plus a tarball installer.

**Phase 2 tests.** CI with a dedicated unprivileged test user: GitHub macOS and Ubuntu runners have passwordless sudo, and Windows runners are admin. Each test runs the "agent" as that user:
- (a) rewrite every user-scope file from §1.1 to `evil` → the `evil` listener receives 0 bytes;
- (b) submit an alert, then `rm -rf ~/.moorai ~/.config/moorai` and kill every user process → the fake console receives the signed alert. Today the job-file deletion drops it;
- (c) planted `console.json` and user `updates:"off"` → the update check goes to the admin console;
- (d) touch the cache, or block the user-level fetch → the helper's beat reports the true policy age;
- (e) remove the hook entry or set `disableAllHooks`, then run a fake `claude` process → helper finding within 3 minutes;
- unprivileged `kill`/`launchctl bootout`/`sc stop`/`systemctl stop` → refused;
- a user binding a fake socket or pipe → the hook refuses it on peer uid/SID;
- the agent re-registers a device key with the token → "device key changed".

### Phase 3: tamper-evident log anchored by the helper (M–L)
- The helper appends every received hook event, its own observations and every alert to a hash-chained log (`record-chain.mjs` format, ported) in root-only state. The head and seq go into every signed beat and alert batch.
- The console stores the last anchored head and verifies continuity on each beat: `seq` is contiguous and `prev` equals the last head. A fork or regression → High "evidence log rewritten" (this catches even a root-level rewrite of already-anchored records).
- Offline backlog: delivered on reconnect; the console checks that the seq range is complete.
- `moorai-verify-chain` runs against both the helper log and the console's anchors.
- The T1+ macOS agent keeps the head in the keychain.
- T1 (hook-only) keeps 1D. The doc says plainly that this is weak.

**Phase 3 tests:**
- delete records 40–45 from the helper store as root → the next beat makes the console flag a gap or fork;
- 24 h offline with 200 alerts → after reconnect the console holds all 200, contiguous;
- T1 naive job-file deletion → `seq-gap`.

### Sizing (rough, not measured)
| Item | Size |
|---|---|
| 1A resolver plus host plus MDM scripts | M |
| 1B iat freshness | S |
| 1C command and env hardening | S |
| 1D seq and head on alerts | S |
| 1E console rules | M |
| 2 helper core plus IPC plus hook client | L |
| 2 per-OS packaging and approval (×3) | L |
| 2 console device keys, beats, sweep | M–L |
| 2 T1+ macOS keychain agent (signing and profile first) | L |
| 3 chain plus anchoring plus verify | M–L |

### Goal coverage after each phase
| Goal | T1 after phase 1 | T2 after phase 1 | T2 after phase 2/3 |
|---|---|---|---|
| (a) redirect | evidence only | **prevented** (admin binding) | prevented; token unreadable |
| (b) suppress alerts | naive deletion detected | same | **prevented** once acked; gaps detected with a signature |
| (c) freeze updates | update lag (forgeable) | **prevented** (admin source) | prevented plus signed lag |
| (d) stale policy | bounded by iat age, reported | same, plus root HWM | **prevented** (helper fetch) plus signed age |
| (e) disable enforcement | coach fallback still possible | **no coach on managed**; hook removal is evidence | signed "agent active, hook silent" |

## 5. Residual risks after all phases
1. **The agent gets root or admin:** NOPASSWD or cached sudo, auto-elevation, a password found on disk, or a local privilege-escalation bug. It can then stop the helper and rewrite state. Phase 3 still exposes rewrites of records already anchored, and the beat gap still shows.
2. **The user, or MDM, disables MoorAI.** Uninstall, unloading the daemon with admin auth, removing the profile. Indistinguishable from decommissioning; the console can only report silence.
3. **An unhooked agent or host:** a new agent binary, a renamed process, an agent inside a container or VM, a host without managed hook settings. Process observation is name-based and best-effort.
4. **A forged hook on hosts that allow user hooks.** Without `allowManagedHooksOnly`, the agent can repoint the hook to a liar that keeps the counters normal. Client-image checks are heuristics.
5. **Same-user read access.** On T1 the agent reads the tenant token and can post forged token-only events. Mitigated on the console by `requireDeviceKeys`.
6. **Detection is probabilistic.** Sleep, network loss and clock drift need grace windows, so findings arrive minutes or hours late, and some silence will be benign.
7. **T0 unenrolled installs** have no console. Coach mode is not a security boundary.
8. **Unverified platform details:** Keychain delete prompts; LaunchAgent eligibility for the data protection keychain; polkit defaults per distro; Claude Code applying settings `env` to hooks; Windows MXC and the icacls owner path (code comments mark these as unmeasured).
9. **Console compromise,** or theft of the policy signing key or device registration path, sits outside this design.
10. **The plain-browser build** still trusts localStorage.

## Sources
- [Apple forums 807782: Some items appear in keychain but not passwords](https://developer.apple.com/forums/thread/807782)
- [Apple forums 836816: Share a keychain item between a macOS app and a CLI app](https://developer.apple.com/forums/thread/836816)
- [Apple forums 719219: SecItem API and the future of file-based keychains](https://developer.apple.com/forums/thread/719219)
- [Apple forums 696431: On Mac Keychains](https://developer.apple.com/forums/thread/696431)
- [scriptingosx: Get Password from Keychain in Shell Scripts](https://scriptingosx.com/2021/04/get-password-from-keychain-in-shell-scripts/)
- [Apple forums 649081: keychain prompts](https://developer.apple.com/forums/thread/649081)
- The TN3137 and SMAppService pages did not render through my fetch. The SMAppService, Windows service, named-pipe and systemd details above are from platform knowledge; check them against the current docs before implementing.

### Critical Files for Implementation
- /Users/itay.glick/Documents/GAI Apps/RAISEME/cli/config.mjs (plus /Users/itay.glick/Documents/GAI Apps/RAISEME/cli/server-mode.mjs)
- /Users/itay.glick/Documents/GAI Apps/RAISEME/cli/hook-core.mjs
- /Users/itay.glick/Documents/GAI Apps/RAISEME/cli/moorai-hook.mjs
- /Users/itay.glick/Documents/GAI Apps/RAISEME/src-tauri/src/console_binding.rs (plus admin_config.rs, console_http.rs)
- /Users/itay.glick/Documents/GAI Apps/RAISEME-server/server/coverage.js (plus server.js, session-summary.js)
