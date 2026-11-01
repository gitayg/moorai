# Contract: `moorai-guardd`, the privileged helper (trust-anchor design, phase 2)

**Status.** Frozen contract for parallel implementation. Design: `docs/proposals/trust-anchors.md` §3.2, §3.3,
§4 Phase 2, §5.
- **macOS:** installable and running. The platform layer is implemented: process table, SIGSTOP suspension and
  `network: "unsupported"`. `guardd/packaging/macos/install.sh --bind` installs the LaunchDaemon and writes the
  console binding, and `install.sh --check` verifies the install unprivileged. The helper registers its key, bound
  with an enrolment secret, and fetches `/api/policy` device-signed (§13.3 item 13). The hook reads its policy
  through the helper (`cli/guardd-policy.mjs`), so console approval receipts reach it once the helper is installed
  and bound.
- **Linux and Windows:** the platform layers are still stubs, so the helper does not start there.
- **Not wired yet:** the hook's other ops (`submit`, `call`, `kill`, `quarantine`).

**What is real today and what is a stub.**

| Area | Real (tested against the golden fixture) | Stub (`todo!()` / throws / 501) |
|---|---|---|
| Rust crate `guardd/` | wire forms (golden), IPC server, state store, device key lifecycle and registration, policy fetch (device-signed, naming the hook's actor, on demand)/verify/cache/LKG/back-off, alert queue and delivery, beat, push channel, observation, quarantine decisions and ordering, Unix socket transport, `main.rs`, `platform::macos` (system info, process table, SIGSTOP suspend; network block unsupported) | `platform::linux`, `platform::windows` (process table, suspend, network block, system info, Windows pipe), `moorai-guardctl` |
| Hook client `cli/guardd-client.mjs` | constants, canonical JSON, framing, request builders, signed-byte forms, hello-proof verify, fallback table, `verifyEndpointOwnership`, `readDevicePub`, `connect`, `GuarddClient.policy` (used by `cli/guardd-policy.mjs` from `loadVerifiedPolicy`) | `GuarddClient` `submit`, `call`, `kill`, `quarantine` |
| Console `server/device-keys*.js` | canonical JSON, signed-byte forms, `verifySignedRequest` (skew, replay, canonical body, binding), command signature verify, tables | register / beat / alerts / commands / sweep / settings logic; every route answers 501 |

The golden fixture is `test/fixtures/guardd/golden.json` (agent repo), copied byte for byte to
`RAISEME-server/test/fixtures/guardd/golden.json`. All three test suites pin its SHA-256 (§11.1).

---

## 1. Roles

- **Helper** (`moorai-guardd`): root on macOS and Linux, a LocalSystem service on Windows (§13.1). Holds
  every trust input of design §1.1 that matters on T2. Only outbound path to the console for credentialed
  calls. Observes agent processes. Suspends and isolates agent trees on quarantine.
- **Hook** (`cli/moorai-hook.mjs` via `cli/guardd-client.mjs`): runs as the user, same as the agent. Still
  verifies policy signatures itself. Talks to the helper over local IPC.
- **Console** (`RAISEME-server`): registers device keys, verifies signed beats and alert batches, sweeps,
  issues signed quarantine / release / kill commands over a device-signed long-poll.
- **Local admin client** (`moorai-guardctl`, future, core-owned): root/Administrator CLI. The only local
  sender of `release`.

Peer checks identify the caller's uid and pid. They cannot tell the hook from the agent (both are the
user's `node`). The helper therefore never trusts the content of a hook message for a security decision
that affects anything other than the caller's own agent tree (§8.3), and its value is the state it holds,
the outbound path it owns, and what it observes on its own.

## 2. Conventions (every wire format below)

| Item | Form |
|---|---|
| Text | UTF-8, no BOM |
| Integers | JSON integers in ±(2^53−1). No floats anywhere on the wire. |
| Hex | lowercase |
| Base64 | standard alphabet, padded |
| Timestamps | ISO 8601 UTC with milliseconds, `YYYY-MM-DDTHH:MM:SS.sssZ` (what `Date#toISOString` emits) |
| Nonce | 16 random bytes as 32 hex |
| Public key | base64 of the 44-byte ed25519 SPKI DER (`302a300506032b6570032100` ‖ raw 32 bytes): the form `parseTrustedKeys` and `policy-sign.js` already use |
| Key id | first 32 hex of sha256(raw 32-byte public key) |
| Device id | first 32 hex of sha256(`moorai-device|v1|` ‖ OS machine id) (§6.4) |
| Signature | ed25519 (RFC 8032, pure), detached, base64 |
| Optional field | omitted when absent, never `null` |
| Session hash | the hook's existing 16-hex session hash |

### 2.1 Canonical JSON

Byte-identical to `canonicalJson` in `cli/hook-core.mjs` and `server/policy-sign.js`, over a restricted
value set: `null`, booleans, strings, safe integers, arrays, plain objects. Object keys are sorted by UTF-16
code unit (JavaScript `Array#sort`; this differs from UTF-8 byte order for astral characters vs U+E000–U+FFFF,
pinned in fixture case 3). Strings are escaped exactly as `JSON.stringify`: `"` and `\` and U+0000–U+001F only
(`\b \t \n \f \r` by name, the rest `\u00xx`); nothing else, not `/`, U+007F or U+2028.

**Every receiver of a frame or of a signed body parses it and rejects it unless the bytes equal
`canonical(parse(bytes))`.** This removes duplicate keys, unsafe integers, whitespace and escape variants as a
source of disagreement between the Node and Rust parsers (the class of bug v1.13.4/v1.13.5 fixed in the model
proxy).

## 3. IPC protocol (hook ↔ helper)

### 3.1 Transport per OS (compiled-in constants, never configurable)

| OS | Endpoint | Directory | Server side |
|---|---|---|---|
| macOS | `/private/var/run/moorai/hook.sock` | `/private/var/run/moorai` root:wheel 0755 | `AF_UNIX` stream, socket root:wheel 0666, bound by the helper at start (stale socket unlinked) |
| Linux | `/run/moorai/hook.sock` | `/run/moorai` root:root 0755 (`RuntimeDirectory=moorai`, `RuntimeDirectoryMode=0755`) | socket unit `moorai-guardd.socket`: `ListenStream=/run/moorai/hook.sock`, socket root:root `SocketMode=0666`; inherited via `LISTEN_FDS` |
| Windows | `\\.\pipe\MoorAI.Hook` | n/a | `CreateNamedPipeW` with `FILE_FLAG_FIRST_PIPE_INSTANCE`, `PIPE_TYPE_BYTE`, `PIPE_REJECT_REMOTE_CLIENTS`, DACL `D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)` (Authenticated Users may read/write but not create instances) |

`/private/var/run` is used on macOS rather than `/var/run` because `/var` is a symlink and the client's
ownership walk refuses symlinks (§3.6). No path, pipe name or directory is read from the environment, a
settings file, the user's config or the command line, on either side. The one environment read in the
helper is systemd's `LISTEN_FDS`/`LISTEN_PID`, only to find an inherited fd.

A connection may carry several requests, strictly sequential (send one, read its reply). The helper closes a
connection after 5 s with no complete frame, or a frame that takes longer than 1 s to arrive, and serves at
most 64 concurrent connections (`busy` beyond).

### 3.2 Framing

`u32` big-endian length N, then N bytes of canonical JSON, one object. `1 ≤ N ≤ 1 048 576` (`MAX_FRAME`; the
signed policy text is the largest message). A receiver checks N before buffering the body. N = 0, N >
`MAX_FRAME`, invalid UTF-8, a BOM, a non-object or non-canonical bytes → the helper answers an `error` frame
(`bad_frame` / `frame_too_large`, `id` 0 when unreadable) and closes; the client closes and treats the helper
as unreachable.

### 3.3 Envelope and versioning

Request `{v, id, op, ...fields}`; response `{v, id, op, ...fields}` where `op` echoes the request's op, or is
`"error"`. `v` is the protocol major, now `1`. `id` is a u32 ≥ 1 chosen by the client, unique per connection.
Unknown fields are ignored (additive changes stay within v1); an unknown `op` is `unknown_op`; a `v` the
helper does not speak is `unsupported_version`. `hello` carries `proto: [majors…]` and the reply names the one
chosen. A breaking change bumps `v` and the helper serves both majors for one release.

### 3.4 Messages

Types: `str`, `int` (safe integer), `u32`, `bool`, `obj`, `[T]`. `?` = optional (omitted when absent).

**`hello`** (any client, first on every connection)

| Request | | Response | |
|---|---|---|---|
| `proto` | `[u32]` ascending | `proto` | `u32` chosen |
| `client` | `"moorai-hook"` \| `"moorai-host"` \| `"moorai-guardctl"` | `helperVersion` | `str` semver |
| `clientVersion` | `str` | `tenant` | `str` |
| `host?` | agent host kind (§8.2) | `deviceId` | `str` 32 hex |
| `nonce` | `str` 32 hex | `keyId` | `str` 32 hex |
| | | `caps` | `[str]` sorted ops served |
| | | `proof` | `str` sig by the device key over `moorai-guardd-hello|v1|<nonce>|<keyId>|<helperVersion>` |

**`policy`**

| Request | | Response | |
|---|---|---|---|
| `ifIat?` | `str` the `policySig.iat` the client holds | `source` | `"fresh"` \| `"cache"` \| `"lkg"` \| `"none"` |
| `actor?` | `str` the hook's keyed actor, `h2:` + 16..64 hex (else `bad_request`); must equal the actor the helper derives for the peer (below) | | |
| | | `policy?` | `str` the signed policy exactly as `GET /api/policy` served it; omitted when `source` is `none` or `ifIat` is current |
| | | `iat?`, `fetchedAt?` | `str` timestamps |
| | | `ageSec?` | `int` now − iat |

`fresh` = verified and younger than `policyMaxAgeMinutes` (default 15); `cache` = verified, older (console
unreachable); `lkg` = last known good; `none` = nothing verified. The hook re-verifies the signature and
applies its own HWM. The helper fetches every 60 s while any `call` or `policy` request arrived in the last
10 min, else every 10 min.

The fetch is `GET /api/policy?tenant=<t>[&actor=<a>]` (`encodeURIComponent` values, the hook's own query form).
The background fetch names no actor. Its policy is the only one ever held as `held`, the cache or the
last-known-good.

**The actor is derived from the peer, not claimed.** For every `policy` request the helper derives the peer's
actor itself (`policy::derive_actor`, `helper::peer_actor`): the peer uid (§3.6, kernel-reported) resolved to its
login name with `getpwuid_r` (the lookup behind the hook's `os.userInfo().username`), the helper's install token
from `secret.json`, and `gethostname` (behind `os.hostname()`), hashed byte for byte as `cli/content-hash.mjs`
`actorHash`: key = HMAC-SHA-256(installToken, `moorai/content-hash/v2`); actor = `h2:` + the first 16 lowercase hex
of HMAC-SHA-256(key, `<user>@<host>`), with no normalisation. Shared vectors:
`guardd/tests/fixtures/actor-vectors.json` (generated from `content-hash.mjs`, tested by both sides).
- a request naming an actor other than the derived one, or naming one when none can be derived, is answered
  `source: "none"` with no fetch (the hook then takes its direct path);
- a request naming no actor is served the derived actor;
- when no actor can be derived (no install token, a uid with no login name, no hostname, or a Windows peer),
  only the actor-less policy is served, never an actor's.

The derived actor is bound to the peer's uid:
- one actor per uid, with the uid's previous actor and its policy dropped;
- an actor is tied to the first uid that binds it for the helper's lifetime: any other uid (two uids with one
  login name) is answered `source: "none"` with no fetch, also after the first uid's binding has been evicted;
- at most 16 uid bindings, least recently used out, in memory only; the actor-to-first-uid ties are never
  evicted, and past 4096 of them a new actor is answered `source: "none"`. Only derived actors are bound, so
  the binding cannot be raced after a helper restart (a restart clears the ties too).

Its fetch names that actor, and its answer is held per actor (in memory, at most 16) and served only to requests
for that actor. Once the device key is
registered, the request is device-signed per §6.2 over exactly that path and query. That gives the console the
per-device credential for approval receipts (RAISEME-server `server/approval-receipts.js` `receiptAuthFor`; a
receipt goes only to a bound key whose device is the request's device, over the posting install token). A
signature the console cannot verify only withholds receipts: the policy is served on the install token
either way.

**On demand.** A `policy` request is answered from that actor's own held policy (or, with no derivable actor,
the actor-less one) when it was fetched within `ON_DEMAND_FRESH_MS` (60 s, the hook's own cache window). Otherwise the helper fetches first, with a
per-request timeout of `ON_DEMAND_FETCH_MS` (1000 ms), and then answers with what it holds. It never fetches on
demand while the console back-off is open, or before a policy key is anchored or pinned (the background loop does
first contact). Fetches carry tickets per actor: an answer that arrives after a later-started fetch for the same
actor was applied is dropped.
The hook uses only a `fresh` answer and otherwise takes its own direct path (§10.3).

**`submit`**

| Request | | Response | |
|---|---|---|---|
| `alerts` | `[obj]` 1..64 alerts in the hook's existing content-free shape | `acks` | `[{seq: int}]` one per alert, same order |
| | | `chainHead` | `str` 64 hex |

The helper overwrites `seq` and `chainHead` from its own root-held chain (`record-chain.mjs` format:
`chash = sha256(prev|seq|rhash)`) and replies **only after the queue entries are fsynced**. Once acked, the
agent cannot delete the alert. The hook awaits the ack before exiting (within `OP_TIMEOUT.submit`).

**`call`**

| Request | | Response |
|---|---|---|
| `event` | `str` hook event (`PreToolUse`, `PostToolUse`, `UserPromptSubmit`, `Stop`, …) | `{}` |
| `host` | `str` §8.2 | |
| `sessionHash` | `str` | |
| `agentPid?` | `u32` hint for observation only | |

Counted per host for the beat's `hookCalls`, and used to map `sessionHash` → agent tree for console session
quarantine.

**`kill`** (replaces the `~/.moorai/kill-session` sentinel, design §1.1 #19; polled by the host every 600 ms
and checked by the hook)

| Request | | Response | |
|---|---|---|---|
| `sessionHash?` | `str` | `kill` | `bool` |
| | | `cmdId?`, `issuedAt?` | `str` |
| | | `scope?` | `"session"` \| `"device"` |

**`quarantine`** (hook → helper, §8)

| Request | | Response | |
|---|---|---|---|
| `agentPid` | `u32` hint; must equal the helper's own derivation (§8.3) | `quarantineId` | `str` `q-` + 16 hex |
| `pgid?`, `sid?` | `u32` Unix process group / session | `suspendedPids` | `u32` |
| `winSessionId?` | `u32` Windows logon session | `suspendedAtMs` | `int` epoch ms, last process confirmed stopped |
| `host` | `str` | `network` | `"pending"` \| `"applied"` \| `"unsupported"` \| `"failed"` |
| `threatId?` / `ruleId?` | `u32` / `str`, exactly one | | |
| `reasonCode` | `str` content-free | | |
| `sessionHash` | `str` | | |
| `decidedAtMs` | `int` epoch ms of the hook's decision | | |

**`release`** (administrator peers only, §3.6; never sent by the hook, and `buildRequest` refuses it)

| Request | | Response | |
|---|---|---|---|
| `quarantineId` | `str` or `"*"` | `released` | `u32` |

**`error`** (response only): `code` (below), `message` (content-free), `reqOp?`.

Error codes: `bad_frame`, `frame_too_large`, `unsupported_version`, `unknown_op`, `bad_request`, `forbidden`,
`not_ready` (no binding / no key yet), `busy`, `target_not_agent_ancestor`, `quarantine_failed`,
`unknown_quarantine`, `internal`.

### 3.5 Timeouts

Client budgets (from the first byte written; on expiry the client closes and applies §10.3):

| Step | Budget |
|---|---|
| connect + ownership check + `hello` + proof verify | **50 ms** (`CONNECT_BUDGET_MS`) |
| `policy` | 50 ms (answered from the held policy); 1300 ms when the helper fetches on demand (`POLICY_FETCH_TIMEOUT_MS`, `OP_TIMEOUT_POLICY_FETCH_MS`) |
| `submit` | 250 ms |
| `call` | 20 ms |
| `kill` | 50 ms |
| `quarantine` | 100 ms (the deny is already decided; this bounds only the wait for the ack) |
| `release` (guardctl) | 2000 ms |

A hook process opens at most one connection per invocation and reuses it for every op.

### 3.6 Peer verification

**Helper side** (kernel facts, never message content):
- macOS: `getsockopt(SOL_LOCAL, LOCAL_PEERCRED)` → `xucred.cr_uid`; `getsockopt(SOL_LOCAL, LOCAL_PEERPID)` → pid.
- Linux: `getsockopt(SOL_SOCKET, SO_PEERCRED)` → `ucred{pid, uid, gid}`.
- Windows: `GetNamedPipeClientProcessId` → `OpenProcess` → `OpenProcessToken` → `TokenUser` SID, `TokenElevation`.
- A connection whose peer cannot be read is closed before any frame is read.
- **Admin peer** = uid 0 (Unix), or a token whose user is SYSTEM (`S-1-5-18`) or that is an elevated member of
  BUILTIN\Administrators (Windows). `release` requires an admin peer (`forbidden` otherwise;
  `helper::authorize` is the single gate and is unit-tested). Every other op is open to any local peer.
- The peer pid and uid are recorded per connection and used by the ops themselves: a `call` counts as
  liveness only for agent processes of the peer's uid (§8.2), and the `sessionHash` → agent tree mapping it
  records belongs to the peer's uid (another uid's `call` never remaps it, and when the map is full the
  eviction comes out of the uid holding the most sessions); `quarantine` derives its target from the peer pid
  (§8.3); `submit` stamps `peerUid` on each queued alert; `policy` derives the peer's actor from its uid (§3.4).
- Rate limits per peer uid: `quarantine` 10/min (`busy` beyond); `submit` 64 alerts per frame.

**Hook side.** Node exposes neither `SO_PEERCRED`/`LOCAL_PEERCRED` nor `GetNamedPipeServerProcessId`, so the
design's client-side SID check (design §3.2) is replaced by two checks, both required:
1. **Endpoint ownership (Unix).** `lstat` every component from `/` to the socket's directory and the socket
   itself: no symlinks; every directory owned by uid 0 and not group- or world-writable; the socket is a
   socket owned by uid 0. A user cannot create an entry in such a directory, so a squatter cannot exist at that path. On
   Windows this step is skipped (the pipe namespace has no owner walk; `FILE_FLAG_FIRST_PIPE_INSTANCE` blocks
   squatting while the service runs).
2. **Device-key proof (all OSes).** The client sends a fresh `nonce` in `hello`; the reply's `proof` must
   verify against `device.pub` read from the run directory (§4) through `readRootOwned` (on Windows the
   icacls check, with the owner-gap caveat of design §1.1 #6), and the reply's `keyId` must equal that key's id.
   A squatter (for example, a user process that grabbed the pipe while the service was stopped) cannot sign.

Failing either check = helper unreachable, plus a content-free tamper alert `helperImpersonation` raised
through §10.3's path.

### 3.7 Kill and host

The desktop host (`moorai-host`) uses the same endpoint and ops (`hello`, `kill`, `policy`). It replaces its
600 ms poll of `~/.moorai/kill-session` with `kill` over IPC when the helper is reachable.

## 4. Helper state layout

### 4.1 Admin inputs (read-only to the helper, written by MDM/installer)

| File | macOS | Linux | Windows |
|---|---|---|---|
| machine config (§10.1) | `/etc/moorai/config.json` root:wheel 0644 | `/etc/moorai/config.json` root:root 0644 | `<PD>\MoorAI\config.json` admin-owned, Users read |
| secret | `/etc/moorai/secret.json` root:wheel **0600** | `/etc/moorai/secret.json` root:root **0600** | `<PD>\MoorAI\secret.json` owner SYSTEM, protected DACL: SYSTEM F + Administrators F only |
| policy anchor (phase 1, optional) | `/etc/moorai/policy.pub` | same | `<PD>\MoorAI\policy.pub` |
| admin HWM (phase 1, optional) | `/etc/moorai/policy-hwm.json` | same | `<PD>\MoorAI\policy-hwm.json` |

All read through the ownership checks `admin_config.rs` implements (`read_owned_under`: `O_NOFOLLOW`, owner of
every ancestor; Windows: HKLM ProgramData + icacls). `<PD>` is ProgramData from
`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList` `ProgramData`, never `%ProgramData%`.

`secret.json`: `{ "installToken"?: str, "enrollSecret"?: str }`, written by MDM (§13.1 decision 4). The
helper removes `enrollSecret` after a successful bound registration (§5.2), rewriting the file with the same
owner and mode.

### 4.2 Helper-owned state

| Item | macOS (helper = root) | Linux (helper = root) | Windows (helper = LocalSystem) |
|---|---|---|---|
| state dir | `/Library/Application Support/MoorAI/state` root:wheel 0700 | `/var/lib/moorai` root:root 0700 (`StateDirectory=moorai`) | `<PD>\MoorAI\state` owner SYSTEM, protected DACL SYSTEM F only |
| run dir | `/private/var/run/moorai` root:wheel 0755 | `/run/moorai` root:root 0755 | `<PD>\MoorAI\run` owner SYSTEM, SYSTEM F + Administrators F + Users R |
| `device.pub` (run dir) | root:wheel 0644 | root:root 0644 | inherits run dir |
| log | `/Library/Logs/MoorAI/guardd.log` root:admin 0640 | journald | Windows Event Log, source `MoorAIGuard` |

Files in the state dir, each 0600 (Unix) or inheriting the protected DACL (Windows), written by temp file +
fsync + rename + fsync(dir):

| File | Content |
|---|---|
| `device.key` | 32-byte ed25519 seed, hex. Generated with the OS CSPRNG at first start. A present but unparseable file is an error, never silently replaced (that would change the key id). |
| `registration.json` | `{keyId, deviceId, registeredAt, status, origin}` of the last successful registration |
| `binding.json` | snapshot of the resolved binding (origin, tenant), for change detection only |
| `policy-cache.json`, `policy-lkg.json` | `{text, iat, fetchedAt}` |
| `policy-pin.json`, `policy-hwm.json` | helper's own pin and rollback mark |
| `posture` | posture ratchet, root-held |
| `backoff.json` | console back-off |
| `alerts/` (0700) | durable queue, one file per acked submit, named by first seq |
| `chain.json` | `{seq, head}` of the alert chain |
| `beat.json` | `{beatSeq, clockOffsetMs, lastBeatAt}` |
| `counters.json` | hook calls per host since last beat |
| `quarantine.json` | quarantine entries and the last applied `cmdSeq` (§8.4–§8.5) |
| `commands.json` | `{lastCmdSeq, recent: [cmdId…]}` |

### 4.3 Service definitions

| OS | Unit | Identity |
|---|---|---|
| macOS | `run.glick.moorai.guardd` LaunchDaemon, **pkg-installed** at `/Library/LaunchDaemons/run.glick.moorai.guardd.plist` (root:wheel 0644); `KeepAlive=true`, `RunAtLoad=true`. SMAppService from the app bundle is a later option. | root (`UserName` unset) |
| Linux | `moorai-guardd.service` + `moorai-guardd.socket` under `/lib/systemd/system`; no `User=` (root); `CapabilityBoundingSet=` limited to what process freeze/stop, process-table reads and nftables need (exact set is the Linux platform agent's, reviewed before release); `ProtectSystem=strict`, `ProtectHome=read-only`, `NoNewPrivileges=yes`, `PrivateTmp=yes`, `StateDirectory=moorai`, `RuntimeDirectory=moorai`, `Restart=always` | root |
| Windows | service `MoorAIGuard`, `C:\Program Files\MoorAI\moorai-guardd.exe`, auto start, recovery: restart ×3 then every 60 s; service DACL set with `SetServiceObjectSecurity` so only SYSTEM and Administrators have `SERVICE_STOP`/`SERVICE_CHANGE_CONFIG` | LocalSystem |

## 5. Device registration

### 5.1 Key and identity

`device.key` is generated at first start. `keyId`, `deviceId` and the public key form are in §2. The machine
id is: macOS `IOPlatformUUID`; Linux `/etc/machine-id`; Windows `HKLM\SOFTWARE\Microsoft\Cryptography`
`MachineGuid`. It is hashed into `deviceId` and never sent raw. `device` is the hostname as the hook already
reports it (the console pseudonymises it), so beats join existing device rows.

### 5.2 `POST /api/devices/register`

Auth: `X-Install-Token` from `secret.json` **and**, for a bound registration, `X-Enroll-Secret` (§5.3). The
request is device-signed (§6.2) **with the new key** whose public half is in the body (proof of possession).

Body (canonical JSON, ≤ 4 KiB):

| Field | Type |
|---|---|
| `v` | `1` |
| `tenant` | `str`, must equal the token's tenant |
| `deviceId` | `str` 32 hex, must equal `X-Device-Id` |
| `device` | `str` hostname |
| `platform` | `"darwin"` \| `"linux"` \| `"win32"` |
| `arch` | `str` (`arm64`, `x64`, …) |
| `helperVersion` | `str` |
| `publicKey` | `str` SPKI base64 |
| `keyId` | `str`, must equal keyId(publicKey) and `X-Device-Key` |
| `prevKeyId?`, `prevKeySig?` | planned rotation: the old key id and its signature over `moorai-rotate|v1|<tenant>|<deviceId>|<oldKeyId>|<newKeyId>` |

Response `201`: `{ok: true, deviceId, keyId, status, bound, serverTime, beatIntervalSec: 300}`.

`bound` is `true` when the device's current key was registered with a valid enrolment secret for this
tenant (and stays true across `unchanged` and `rotated`). `status`:

| `status` | When | `bound` after | Finding |
|---|---|---|---|
| `registered` | no row for (tenant, deviceId) | true with a valid secret, else false | none when bound; Low "Device registered unbound" when not |
| `unchanged` | same keyId as the current row | unchanged | none |
| `rotated` | different key, `prevKeySig` verifies with the current key | unchanged | Info "Device key rotated" |
| `reenrolled` | different key, no valid `prevKeySig`, valid enrolment secret | true | Medium "Device re-enrolled with a new key" |
| `changed` | different key, no valid `prevKeySig`, no valid enrolment secret | **false** | **High "Device key changed"** |

A changed key is accepted (the console cannot tell a reinstall from an attack), flagged High, and the device
becomes unbound until it re-enrols. The old key moves to `device_key_history` and stops verifying. Errors:
`400` malformed / non-canonical / mismatched fields, `401` bad token, bad enrolment secret or bad signature
(`verifySignedRequest` codes plus `bad_enroll_secret`), `409` replay, `413` too large. A present but invalid
`X-Enroll-Secret` is refused (`401 bad_enroll_secret`), never downgraded to an unbound registration.

**Why binding matters.** The install token is per tenant, and phase 1 left it in the user's 0600 file on T1
devices of the same tenant (design §1.2, §4 1A). An agent on any T1 device of the tenant therefore holds a
token that can register a key for any `deviceId`. Only a per-device, one-time, root-delivered enrolment
secret makes registration unforgeable from user scope. Under `requireDeviceKeys` (§9.6), only bound devices'
signed beats and alerts count as trusted.

### 5.3 Enrolment secrets (console-issued, one-time, per device)

Format `mes_` + 32 hex. The console stores only sha256(secret). Each secret is single-use, bound to one
tenant, valid 30 days, and bound to a `deviceId` either at issue time (if the admin names one) or at first
use. MDM writes it to `secret.json` `enrollSecret` alongside the install token (§4.1).

| Route | Auth | Request | Response |
|---|---|---|---|
| `POST /api/devices/enroll-secrets` | admin session (account sessions locked to their tenant) | `{count: 1..1000, deviceId?: str, label?: str}` (`deviceId` only with `count: 1`) | `201 {secrets: [{id, secret, deviceId?, expiresAt}]}`; the secret values are shown once |
| `GET /api/devices/enroll-secrets` | admin session | `?state=unused\|used\|expired\|revoked` | `{secrets: [{id, label, deviceId?, createdAt, expiresAt, usedAt?, usedByDeviceId?, revokedAt?}]}`, never the secret |
| `POST /api/devices/enroll-secrets/revoke` | admin session | `{id}` or `{label}` | `{revoked: int}` |

The MDM deploy flow: an admin issues a batch (CSV export from the console UI) and the MDM script assigns one
secret per device. Issuing, revoking and each use are written to the governance log (ids and labels only).

## 6. Signed heartbeat

### 6.1 `POST /api/devices/beat` body (canonical JSON, ≤ 16 KiB)

| Field | Type | Meaning |
|---|---|---|
| `v` | `1` | |
| `tenant`, `deviceId`, `device`, `platform`, `keyId` | `str` | as §5 |
| `bootId` | `str` | §6.4 |
| `awakeSec` | `int` | seconds awake since boot, **excluding** sleep |
| `uptimeSec` | `int` | seconds since boot, including sleep |
| `beatSeq` | `int` | strictly increasing per key, persisted before sending, never reused |
| `chainSeq`, `chainHead` | `int`, `str` | the helper's alert chain (phase 3 anchors it) |
| `policyIat?`, `policyFetchedAt?` | `str` | the policy the helper holds |
| `policySource` | `"fresh"` \| `"cache"` \| `"lkg"` \| `"none"` | |
| `hookCalls` | `{host: int}` | `call`s per host since the previous beat |
| `agentProcs` | `{host: int}` | agent host processes per host at beat time |
| `hookSilent` | `[{host: str, sinceSec: int}]` sorted by host | hosts with a process running ≥ 120 s and zero calls |
| `quarantinesActive` | `int` | |
| `versions` | `{helper: str, hook?: str, app?: str}` | |
| `clockOffsetMs` | `int` | offset the helper applies to its clock (§6.5) |
| `helperStartedAt` | `str` | |

Cadence: every 300 s, plus one immediately at start and one at clean shutdown.

### 6.2 Signing (beats, alert batches, registration, command poll and ack)

Headers on every device-signed request:

| Header | Value |
|---|---|
| `X-Install-Token` | from `secret.json` (or `X-Enroll-Secret` on register) |
| `X-Device-Id` | deviceId |
| `X-Device-Key` | keyId |
| `X-Device-Ts` | timestamp (§2), helper clock + `clockOffsetMs` |
| `X-Device-Nonce` | fresh nonce |
| `X-Device-Sig` | signature over the signing input |

Signing input (UTF-8):

```
moorai-devreq|v1|<METHOD>|<path-and-query>|<tenant>|<deviceId>|<keyId>|<ts>|<nonce>|<sha256hex(body bytes)>
```

`<path-and-query>` is exactly as sent (`/api/devices/commands?after=6&wait=25`); the body is the exact bytes
sent (empty for GET). For every POST the body is canonical JSON whose `tenant` and `deviceId` equal the token
tenant and `X-Device-Id`.

Console check order (`verifySignedRequest`, implemented): header shapes → skew → current key for
(tenant, deviceId, keyId) → signature → nonce replay → body canonical → body binding. Codes:
`bad_signature_headers` 401, `clock_skew` 401 (+`serverTime`), `unknown_key` 401, `bad_signature` 401,
`replay` 409, `non_canonical` 400, `binding_mismatch` 400. The nonce is recorded only after the signature
verifies, so unauthenticated junk cannot fill the cache.

### 6.3 Replay protection

- `(keyId, nonce)` is accepted once; the console keeps nonces 600 s (`NONCE_TTL_MS`), twice the skew window.
- Beats additionally require `beatSeq` > the stored one for that key; equal or lower → `409 replay` and High
  "Device beat replayed or rewound".
- Alert batches are idempotent on `batchId` (`409 duplicate` = already ingested; the helper treats it as
  delivered).

### 6.4 Boot id and clocks

| | `bootId` | `awakeSec` | `uptimeSec` |
|---|---|---|---|
| macOS | `sysctl kern.bootsessionuuid` | `clock_gettime(CLOCK_UPTIME_RAW)` | now − `kern.boottime` |
| Linux | `/proc/sys/kernel/random/boot_id` | `clock_gettime(CLOCK_MONOTONIC)` | `clock_gettime(CLOCK_BOOTTIME)` |
| Windows | GUID formatted from sha256 of the boot time (now − `GetTickCount64`, rounded to 10 s) | `QueryUnbiasedInterruptTime` | `GetTickCount64` |

### 6.5 Clock skew

The console rejects `|now − ts| > 300 s` with `401 {error:"clock_skew", serverTime}`. The helper then sets
`clockOffsetMs = serverTime − local` (bounded to ±24 h), re-signs with a fresh nonce and retries once. It
reports the offset in every beat; `|clockOffsetMs| > 300 000` is a Low "Device clock skew" finding. The offset
is never applied to `awakeSec`/`uptimeSec`.

## 7. Signed alert batches

### 7.1 Queue and delivery

`submit` → stamp seq/head → fsync → ack. A delivery thread sends batches oldest first: ≤ 64 alerts and
≤ 256 KiB per batch, contiguous seq. Retry after failure: full-jitter exponential from 5 s, cap 300 s. Queue
bound 10 000 alerts; beyond it the oldest non-quarantine alerts are dropped and `queueOverflow` carries the
count on the next batch.

### 7.2 `POST /api/devices/alerts` body (canonical JSON, device-signed per §6.2)

| Field | Type |
|---|---|
| `v` | `1` |
| `tenant`, `deviceId` | `str` |
| `batchId` | `str` 32 hex, kept across retries |
| `firstSeq`, `lastSeq` | `int` |
| `chainHead` | `str` head after `lastSeq` |
| `alerts` | `[obj]`, each the hook's alert object plus `seq` (and `peerUid`) |
| `queueOverflow?` | `int` |

The console unpacks each alert into the existing ingest (`store.insertAlert`) with `device_signed = 1`,
`device_key_id`, and the seq. **"The canonical form over (body, ts, nonce)"** of the brief is exactly §6.2's
signing input: body hash, ts and nonce are all inside it, along with method, path and the binding.

**Token-only alerts.** A `POST /api/alerts` (the phase 1 path) naming a `device` that has a registered key →
Medium "Token-only alert from helper-managed device". With `requireDeviceKeys` on, such alerts and
token-only `/api/agent-posture` beats are stored with `trust = 'untrusted'` and excluded from metrics.

## 8. Quarantine

### 8.1 Policy action

`quarantine` joins the threat actions (`notify`, `block`, `kill`, `justify`, `mask`, `ask`) in
`threatPolicy` / `tierPolicy` and in tool/rule actions. When the hook decides `quarantine` it (1) denies the
action exactly as `block` does, (2) sends `quarantine` over IPC (§3.4) and (3) raises the alert. The deny
never waits on the helper.

### 8.2 Agent hosts and observation

The table `observe::AGENT_HOSTS` (same table for observation and for §8.3):

| host | image basenames | interpreter + argv[1] suffix |
|---|---|---|
| `claude-code` | `claude` | `node`/`bun` + `@anthropic-ai/claude-code/cli.js` |
| `codex` | `codex` | `node` + `@openai/codex/bin/codex.js` |
| `gemini` | `gemini` | `node` + `@google/gemini-cli/dist/index.js` |
| `copilot` | `copilot` | `node` + `@github/copilot/index.js` |
| `cursor` | `cursor`, `cursor-agent` | none |

Match on the kernel's image path (`proc_pidpath`, `/proc/<pid>/exe`, `QueryFullProcessImageNameW`), basename
without `.exe`, case-insensitive on macOS/Windows; argv[1] from `KERN_PROCARGS2`, `/proc/<pid>/cmdline` or the
PEB. Name-based and best-effort (design §5 risk 3); the entries must be confirmed on real installs (§13.2).
Observation scans every 15 s; a host with a matching process for ≥ 120 s and zero `call`s for that host from
a peer of the process's own OS user is `hookSilent` in the next beat and raises a signed local alert once per
process. A call vouches only for its peer's own user: another account's calls never keep this user's agent
from reading as silent.

### 8.3 Target rule

The request names a pid; the helper never trusts it. It accepts a `quarantine` only when, from its own
reading of the OS process table (parent links checked against process start times, so a reused pid cannot
be spliced into a chain):
- (a) the named pid exists;
- (b) its ancestry contains a process that matches an `AGENT_HOSTS` entry (§8.2);
- (c) that agent host process runs under the same OS user as the IPC peer (§3.6, kernel-reported), and is
  never pid ≤ 1, a uid 0 / SYSTEM process (unless the peer is too), or the helper itself.

The target set is that agent host process and all of its descendants, as the helper enumerates them. The
requesting hook process is left running until it has read the ack. A request that fails any check is
refused with `target_not_agent_ancestor` (§3.4) and raises a signed Medium "Quarantine target refused" alert,
because a hook that names a non-agent process is itself a tamper signal. The hook's deny stands either way.

Who may trigger what:
- **Quarantine:** the hook over IPC (bounded by the rule above), or a verified console command (§9.3). For a
  console command, scope `session` targets the tree the helper has mapped from `sessionHash` via `call`
  (§3.4); scope `device` targets every tree on the device that matches `AGENT_HOSTS`.
- **Release:** an admin source only. That is either a verified console command, or the root-local CLI
  `moorai-guardctl release <id|*>`, which sends the IPC `release` op as an admin peer. The hook can never
  release, and `moorai-guardd` itself takes no arguments (§10.2).

### 8.4 Effect, ordering and latency

1. Verify the target (§8.3).
2. Persist the quarantine entry (state `quarantine.json`, §4.2) before acting, so a restart re-applies it.
3. Suspend the target set: macOS and Linux use a stop signal, or a cgroup freeze where available; Windows
   uses a job object or process suspend. Processes are frozen, not killed, so state and evidence survive
   review.
4. Reply to the hook (`network: "pending"`).
5. Block the target set's network: a macOS Network Extension content filter (§13.1 decision 8; `networkBlock: "unavailable"` when absent), Linux nftables matched on
   cgroup, a Windows WFP filter by process. Where MXC or Seatbelt containment is active, its policy switches
   to deny-all. The quarantine state is always persisted (step 2) before this step.
6. Persist the network-block result, then send a signed quarantine alert (§7) with the threat id or rule id
   and the reason code, content-free.

Latency targets:
- hook decision (`decidedAtMs`) to target set suspended (`suspendedAtMs`): **under 50 ms**, local;
- console command creation to suspended: **under 2 s** with the push channel connected (§9.3).

How these are measured is in §11.4. The per-OS mechanics belong to the platform owners (§12).

### 8.5 Release and restart

A release persists the entry as released first, then removes the network block, then resumes the processes
whose start time still matches. On helper start:
- active entries are re-applied (re-suspend matching pids, re-apply the block);
- released entries stay released and are never re-suspended.

Console commands carry a per-device `cmdSeq`. The helper persists the last one it applied and ignores lower
ones, so an old quarantine command cannot replay after a release, across restarts included.

### 8.6 Failure semantics

- **Helper absent or unreachable:** the hook still denies and stamps `quarantineUnavailable` on the alert
  (§10.3).
- **Target refused:** the deny stands; a signed refusal alert is sent (§8.3).
- **Network block fails:** the processes stay suspended, the entry records `network: "failed"`, and the alert
  says which step failed.
- **Suspension fails:** `quarantine_failed` is returned to the hook, which keeps its deny and stamps
  `quarantineUnavailable`.

## 9. Console

### 9.1 Routes

| Route | Auth | Section |
|---|---|---|
| `POST /api/devices/register` | install token (+ enrolment secret), device-signed | §5.2 |
| `POST /api/devices/beat` | install token, device-signed | §6 |
| `POST /api/devices/alerts` | install token, device-signed | §7 |
| `GET /api/devices/commands?after=<cmdSeq>&wait=25` | install token, device-signed | §9.3 |
| `POST /api/devices/commands/ack` | install token, device-signed | §9.3 |
| `GET /api/devices`, `GET /api/devices/quarantines` | admin session | fleet views |
| `POST /api/devices/quarantine` `{deviceId, scope: "device"\|"session", sessionHash?, reason}` | admin session | §8.3 |
| `POST /api/devices/release` `{deviceId, quarantineId \| "*"}` | admin session | §8.5 |
| `POST /api/settings/device-keys` `{requireDeviceKeys: bool}` | admin session | §9.6 |
| `POST/GET /api/devices/enroll-secrets`, `POST /api/devices/enroll-secrets/revoke` | admin session | §5.3 |

All but the enrol-secret routes are registered in `server/device-keys-routes.js` and answer 501. The
enrol-secret routes are still to be added by the console owner.

### 9.2 Tables

`server/device-key-tables.js` creates these today:
- `device_keys`: the current key and last beat per (tenant, device_id);
- `device_key_history`: every key and how it replaced the previous one;
- `device_beats`: accepted beats, kept 7 days;
- `device_nonces`: the replay window;
- `device_alert_batches`: batchId dedupe;
- `device_commands`: quarantine / release / kill, with per-device `cmd_seq`, signature and ack fields;
- `device_quarantines`.

Still to add (console owner):
- a `bound` column on `device_keys` and `device_key_history`;
- `device_enroll_secrets` (hashed secret, tenant, optional device_id, expiry, used/revoked);
- `device_findings_state` for sweep dedupe.

### 9.3 Push channel

The helper holds one device-signed long-poll, `GET /api/devices/commands?after=<lastCmdSeq>&wait=25`:
- **Console side:** holds the poll up to 25 s, then answers `200 {v, commands: [...]}` (ascending `cmdSeq`,
  all above `after`) or `204`. A new poll from the same device replaces any open one, which then gets 204.
- **Helper side:** re-polls at once after any 200 or 204. After an error it backs off with full jitter, from
  1 s and capped at 60 s, resetting on success. A `401 clock_skew` adopts the offset (§6.5); a
  `401 unknown_key` triggers re-registration.
- **Signing:** each command is signed with the tenant's **policy** key over
  `moorai-cmd|v1|<tenant>|<deviceId>|<cmdId>|<cmdSeq>|<action>|<scope>|<sessionHash>|<quarantineId>|<iat>`.
  The helper verifies it with the same anchor or pin that verifies policy. It refuses `cmdSeq` ≤ the
  persisted last one, and acks a command older than 24 h as `stale`.
- **Ack:** the helper sends `POST /api/devices/commands/ack` with `{v, tenant, deviceId, cmdId, cmdSeq,
  result, quarantineId?, suspendedPids?, suspendedAtMs?, network?}`.

Long-poll rather than WebSocket: the lockfile has an HTTP client and no WebSocket client, and long-poll
passes through proxies with one code path. WebSocket is a later option.

### 9.4 Registration binding

As §5.2–§5.3:
- **Valid enrolment secret:** the key is marked `bound`.
- **No secret:** the key is accepted as `unbound`.
- **Key change on a bound device without a rotation signature or a new secret:** accepted, High "Device key
  changed", and the device becomes unbound.
- **Key change on an unbound device:** accepted, High "Device key changed".

### 9.5 Sweep findings

Run every 15 minutes; deduped per device and finding for 24 h. Severities use the console's existing
high / medium / low / info scale.

| Finding | Rule and threshold | Severity |
|---|---|---|
| Helper stopped while device up | No beat for > 900 s (3 intervals). The next beat has the same `bootId` and its `awakeSec` advanced by at least (wall gap − 120 s), i.e. the device was awake through the gap. | High |
| Device offline / asleep | No beat for > 900 s, and the next beat has a new `bootId`, or `awakeSec` shows sleep, or no beat yet | Info |
| Agent active, hook silent | `hookSilent` non-empty in a beat, or `agentProcs[host] > 0` with `hookCalls[host] = 0` in 3 consecutive beats | High |
| Device key changed | §9.4 | High |
| Device registered unbound | §5.2 | Low |
| Device re-enrolled with a new key | §5.2 | Medium |
| Token-only alert from helper-managed device | §7.2 | Medium |
| Device beat replayed or rewound | `beatSeq` not above the stored one, or `awakeSec` decreasing with the same `bootId` | High |
| Quarantine not applied | console command not acked within 30 s while the device is beating | Medium |
| Quarantine target refused | signed refusal alert (§8.3) | Medium |
| Device clock skew | `|clockOffsetMs|` > 300 000 | Low |

### 9.6 `requireDeviceKeys`

A tenant setting, off by default. When it is on:
- token-only alerts and posture from devices that have a registered key are stored as `untrusted` and
  excluded from metrics;
- signed data from **unbound** devices is labelled "signed, unbound";
- the fleet view lists devices with no key or an unbound key.

## 10. Admin file and hook fallback

### 10.1 Fields

New machine-config fields, in `/etc/moorai/config.json` and `<PD>\MoorAI\config.json`, read through the
existing ownership checks:

| Field | Values | Default |
|---|---|---|
| `helper` | `"required"` \| `"optional"` \| `"off"` | `"optional"` (also for any unknown value) |
| `helperMinVersion` | semver; a helper whose `hello.helperVersion` is lower counts as outdated | none |

`serverUrl` and `tenant` keep their phase 1 meaning. The install token and the enrolment secret are never in
this file; they live in `secret.json` (§4.1).

### 10.2 No override

The hook and the helper never take the socket path, pipe name, state paths, `helper` mode or console origin
from the environment, a user file or a command line. `moorai-guardd` accepts no arguments except
`--build-info`. Test path injection exists only in builds with the `test-injection` feature
(`Paths::under`), and `Helper::new` refuses injected paths when running as root or SYSTEM.

### 10.3 Fallback rules

Reachable means connect, ownership check and hello proof all passed within the 50 ms budget (§3.5, §3.6).
`cli/guardd-client.mjs` `fallbackMode()` implements this table:

| Helper state | `off` | `optional` | `required` |
|---|---|---|---|
| Reachable, verified, not outdated | phase 1 behaviour, no IPC | helper used for policy, alerts, counters, kill, quarantine | same |
| Absent (no socket / pipe) or timed out | phase 1 behaviour | phase 1 behaviour | enforce with the posture ratchet (never coach); stamp `helperUnreachable` |
| Present but fails verification | phase 1 behaviour | treated as absent, plus tamper alert `helperImpersonation` | as absent, plus the tamper alert |
| Reachable but outdated | phase 1 behaviour | phase 1 behaviour | as absent; stamp `helperOutdated` |

Quarantine without the helper: the deny always happens, and the alert carries `quarantineUnavailable` (§8.6).
Alerts raised in the posture path go to the best-effort user-scope queue. The console sees the beat gap
independently.

## 11. Test strategy

### 11.1 Golden fixtures

Every wire form is pinned by `test/fixtures/guardd/golden.json`. Its SHA-256 is pinned in all three suites
(`guardd/tests/golden.rs`, `test/guardd-client.test.mjs`, console `test/device-keys.test.js`), and the
console holds a byte-identical copy. `generate.mjs` regenerates the fixture from `node:crypto` alone. A
contract change updates the fixture, the three hashes and the console copy together.

### 11.2 Unit (unprivileged)

- **Rust:** the helper runs over `Paths::under(<tmpdir>)` in `cargo test` and in the `moorai-guardd-test`
  binary (`--features test-injection`), with fake `ProcessSource` / `QuarantineBackend` implementations, so
  the §8.3 rule and the §8.4–§8.5 ordering are tested without privileges. Packaging builds never enable the
  feature. CI asserts `moorai-guardd --build-info` prints `test-injection=false` for the packaged binary.
- **Node:** the hook client is tested against an in-process fake helper speaking the fixture frames.
- **Console:** in-process plus a spawned server, as the existing route tests do.

### 11.3 CI with a real install

**macOS and Ubuntu runners** (passwordless sudo):
- install the real package (pkg / deb) as root;
- create a dedicated unprivileged user, `mooraitest`, with no sudo rights and not in an admin group;
- run every "agent" step as that user (`sudo -u mooraitest -H …`).

**Windows runner** (admin):
- install the service as admin;
- create a standard user (not in Administrators);
- run agent steps as that user through a scheduled task or `CreateProcessWithLogonW`.

Tests:
- the design's phase 2 tests (a)–(e);
- the test user cannot stop or reconfigure the service, read the state dir, or bind a fake socket or pipe
  that the hook accepts;
- re-registering with the tenant token alone gives "Device key changed" and `bound: false`;
- a `quarantine` naming a pid outside any agent-host tree, or one under another user, is refused;
- a release survives a helper restart, and a restart re-applies an active quarantine;
- `release` from the test user is `forbidden`.

### 11.4 Latency measurement

- **Hook-triggered (target < 50 ms):** a stand-in agent host (a long-running test program named per
  `AGENT_HOSTS`) runs as the test user, with a child process and the hook client under it. The hook client
  records `decidedAtMs` and sends `quarantine`. The helper reports `suspendedAtMs` once the last process is
  confirmed stopped. Both read the same host clock, so latency = `suspendedAtMs − decidedAtMs`. The test also
  confirms the stopped state independently from the OS process table. 20 runs; fail if p95 ≥ 50 ms; report
  max and p95.
- **Console-triggered (target < 2 s):** the test console (same host) creates the command with the push
  channel connected. Latency = ack `suspendedAtMs` − command creation time. 10 runs; fail if p95 ≥ 2000 ms.

### 11.5 CI task to add first

CI runs no `cargo test` for `src-tauri` or `guardd` today; the only Rust step is a Windows `cargo check` of
`src-tauri`. Add:
- `cargo test --manifest-path guardd/Cargo.toml` on macOS, Ubuntu and Windows;
- `cargo test --manifest-path src-tauri/Cargo.toml`;
- the `--build-info` check.

### 11.6 Not provable in CI

- MDM delivery and approval on a managed Mac or an Intune device;
- per-distro polkit and systemd differences;
- real agent installs matching `AGENT_HOSTS`;
- the Windows icacls owner-gap behaviour (design §1.1 #6).

## 12. Ownership map

One agent per row. Nobody edits a row they don't own. The shared fixture, this contract and the
`ipc/messages.rs` / `signing.rs` wire types change only through the orchestrator.

| Area | Owner |
|---|---|
| `guardd/src/{lib,main,canonical,keys,signing,config,state,policy,alerts,beat,observe,quarantine,push,console,helper}.rs`, `guardd/src/ipc/*`, `guardd/src/transport/{mod,unix}.rs`, `guardd/src/bin/*`, `guardd/tests/*`, the `moorai-guardctl` CLI | guardd core (decision, target rule, IPC, state) |
| `cli/guardd-client.mjs`, `test/guardd-client*.test.mjs`, hook wiring in `cli/moorai-hook.mjs` / `cli/hook-core.mjs` (the `quarantine` action, fallback, stamps), host `kill` over IPC | hook client |
| console `server/device-keys*.js`, `server/device-key-tables.js`, the `quarantine` action in console policy, sweep, UI, `test/device-keys*.test.js` | console |
| `guardd/src/platform/macos/*` (process table, suspend, network block), LaunchDaemon plist, pkg | platform macOS |
| `guardd/src/platform/windows/*` (pipe, process table, suspend, WFP), service install and DACL | platform Windows |
| `guardd/src/platform/linux/*` (process table, freeze, nftables), systemd units, deb/rpm | platform Linux |
| `packaging/mdm/*`: `secret.json` delivery, enrolment secret, the `helper` field | MDM packaging |
| `.github/workflows/*`: cargo test jobs, real-install jobs, latency jobs | CI |

The scaffolding has stale comments that the owners should fix:
- `config.rs` (fixed by guardd core) and `cli/guardd-client.mjs` still mention a Linux `moorai` user, and the Linux secret mode
  `0640`. Both are superseded by §4 (root, `0600`).
- `console.rs` `RegisterResp.status` lacks `reenrolled` and has no `bound` field (fixed by guardd core).
- The console route file lacks the enrol-secret routes.

## 13. Decisions and open questions

### 13.1 Decided

1. **macOS:** a pkg-installed LaunchDaemon (`/Library/LaunchDaemons/run.glick.moorai.guardd.plist`) is the
   primary path, because it works for MDM and CLI-only fleets. SMAppService from the app bundle is a later
   option. The socket stays at `/private/var/run/moorai/hook.sock`.
2. **Windows:** a LocalSystem service with an explicit service DACL that limits stop and config to
   Administrators and SYSTEM, because quarantine and WFP need it.
3. **Linux:** root under systemd hardening (capability bounding set limited to what freeze and nftables
   need, `ProtectSystem=strict`, `ProtectHome=read-only`, `NoNewPrivileges`, `PrivateTmp`), because a dedicated
   user cannot quarantine.
4. **Token delivery:** MDM writes the tenant install token to a root-only secret file (`/etc/moorai/secret.json`
   0600 root; `<PD>\MoorAI\secret.json` SYSTEM/Administrators only), because the helper is its only reader.
5. **Registration binding:** a console-issued, one-time, per-device enrolment secret binds registration
   (§5.2–§5.3), so a T1 device holding only the tenant token cannot register a key for another device id.
   Unbound registration is accepted and marked.
6. **Quarantine target rule:** the helper re-derives the target from its own process-table reading. It
   requires an agent-host ancestor under the IPC peer's OS user (§8.3), so the agent-controllable hook
   cannot aim it at arbitrary processes. Release is admin-only.

7. **Peer ancestry (was open):** for `quarantine`, the agent host process must be an ancestor of the
   calling hook process as well as of the target pid, so a hook in one session cannot quarantine another
   session. A mismatch is `target_not_agent_ancestor` plus the signed refusal alert (§8.3).
8. **macOS network block (was open):** a Network Extension content filter (MDM-approved system extension).
   When it is not installed or not approved, quarantine still suspends the processes, and the alert and the
   quarantine record carry `networkBlock: "unavailable"` (wire `network: "unsupported"`). pf is not used,
   because it cannot target a process.
9. **Hook-side peer check (was open):** endpoint path ownership plus the signed `hello` proof (§3.6) is
   accepted for now; no native helper for the hook.
10. **MDM enrolment secrets (was open):** besides the console UI CSV, an admin API route (admin API key or
    admin session) returns N one-time secrets for scripted deployment. Console owner.
11. **Agent-host table:** stays name-based; the entries are confirmed on real installs by the platform
    agents (§8.2).
12. **Policy-key rotation on a pinned helper:** see §13.3 item 1.

### 13.2 Open

- **Agent-host table entries:** confirmation on real installs (§8.2, decision 11).

### 13.3 Implementation notes and deviations (guardd core)

Recorded by the guardd core implementation; each is the safest reading of an underspecified or
contradictory point, to be folded into the sections above.

1. **Pinned policy keys rotate only through a signed list (security fix).** Once the helper holds a pin, it
   never fetches or trusts `GET /api/policy/pubkey`. A new key is learned only from `nextKeys` (an array of
   SPKI base64 / PEM) inside a policy body that verifies under an already-pinned key, and only when that
   policy's `iat` is strictly greater than the current high-water mark; a `nextKeys` at or below the mark is
   ignored and reported (`{source: "nextKeys", status: "not-newer"}`). The unsigned endpoint is used only on
   first contact (TOFU), after which the pin locks. `nextKeys` is covered by the policy digest; the console
   must emit it to rotate (console owner). The JS hook (`cli/hook-core.mjs` `policyKeysToLearn`) follows the
   same rule since agent v1.13.7; before that it learned the published keys on a pinned device, which with the
   non-strict rollback rule let a console impersonator replay the current signed policy and get its own key
   pinned. The console emits `nextKeys` during a rotation's transition window (`POST /api/policy/rotate-key`,
   console 0.84.0). Shared scenarios: `test/fixtures/guardd/policy-rotation-vectors.json`.
2. **macOS `/private/var/run` is `root:daemon 0775`.** The helper's ancestor walk accepts a group-writable
   directory only when its group is gid 0, or gid 1 (`daemon`) on macOS. §3.6's hook-side walk ("not group-
   or world-writable") would refuse every Mac as written; the hook client needs the same exception.
3. **fsync means fsync(2).** State writes use `fsync(2)` on the file and the directory, not macOS
   `F_FULLFSYNC` (10–30 ms each, which put `submit` near its budget). Durability across power loss on macOS
   is therefore not claimed. Measured server latencies (macOS, debug build): hello 0.3 ms, call 0.07 ms,
   submit 0.5–1 ms, quarantine 0.4–0.9 ms.
4. **Hook-call counters** are kept in memory on the `call` path and persisted every observation scan (15 s)
   and after each accepted beat; a crash loses at most 15 s of counts. The beat's `hookCalls` are counted per
   host (the beat's shape); liveness for `hookSilent` and session mapping are per peer uid (§3.6, §8.2,
   agent v1.13.8).
5. **Quarantine target:** the helper derives the agent from the peer's ancestry (decision 7); the request's
   `agentPid` is accepted when it is that agent or any descendant of it, and the request's `host` must equal
   the derived host. pid ≤ 1, the helper itself and uid-0 processes (for a non-root peer) are refused.
6. **Quarantine record fields:** entries add `networkBlock` (`"unavailable"`), `failedStep` (`suspend` |
   `network` | `unblock` | `resume`) and `suspendedAtMs`; `quarantine.json` holds `lastCmdSeq`. The wire
   `NetBlockState` has no `unavailable`, so the IPC reply and ack say `unsupported`.
7. **Requesting hook process:** it is excluded from the suspended set, then suspended after a 2 s grace if
   the same process (by start time) is still alive. The helper never suspends itself.
8. **Failures:** a failed suspend returns `quarantine_failed`, keeps the entry Active with
   `failedStep: "suspend"` (a restart retries) and sends the alert. A release whose unblock or resume failed
   stays released and is retried at start.
9. **Console quarantine:** `device` scope is one entry spanning every agent tree (one `quarantineId` in the
   ack); `session` scope uses the tree the helper mapped from the `call` peer's own ancestry, never the
   `agentPid` hint. uid-0 agents and the helper are never console targets. No target → ack `ignored`.
10. **Commands:** an unpinned helper verifies no command (`bad-signature`). `bad-signature` never advances
    `lastCmdSeq` (a forged huge `cmdSeq` cannot block real ones); `stale` advances it; replay, mismatch and
    malformed ack `ignored`. `lastCmdSeq` is persisted before a command acts. A `kill` command is held in
    memory for 10 min; `kill` without `sessionHash` reports only device-scope kills.
11. **IPC envelope:** `hello` needs a binding (`not_ready` otherwise). A first frame other than `hello` is
    `bad_request` and closes; a frame without a readable `id` is `bad_request` with id 0 and closes;
    `unsupported_version`, `unknown_op` and malformed fields keep the connection. Server-side limits are the
    5 s idle / 1 s frame deadlines, a 1 s write timeout and the 64-connection cap.
12. **Admin inputs:** a `secret.json` readable by group or other is refused (no binding). The ownership walk
    of `read_owned_under` stops at the trust root: `/` for the system paths (unchanged), the injected root
    for a `test-injection` tree. A tenant change in the admin binding (detected through `binding.json`)
    drops the pin, mark, cache and last-known-good and re-registers.
13. **Policy:** fetched with the install token and, once the device key is registered, device-signed (§6.2,
    `GET`, path and query as sent, empty body), naming the actor the helper derives for the IPC peer (equal to
    the hook's actor, §3.4); fetched on demand per §3.4. Before
    agent v1.32.0 it was fetched with the install token only, so no console receipt could reach the hook.
    Freshness is measured from `iat`, else from `fetchedAt` (an unsigned console). Last-known-good is written
    only for a real signature (`ok` or a TOFU arm). The `/api/policy/pubkey` first-contact fetch stays unsigned.
14. **Alert chain:** genesis is record-chain's `genesis("guardd-alerts", tenant)`, so before the first alert
    the beat's `chainHead` is `g:` + 24 hex, not 64 hex. `rhash` is `recordRhash` of the stamped alert minus
    `seq`. The overflow rule also spares the batch in flight; a `413` drops that batch and counts it as
    overflow; `409 duplicate` counts as delivered; `401 unknown_key` triggers re-registration.
15. **Beat:** on `401 clock_skew` the beat is rebuilt with a new `beatSeq` (the old one was persisted and is
    never reused); `hookCalls` are subtracted only after an accepted beat.
16. **Registration and keys:** a planned rotation stages `device.key.next` (a state file §4.2 does not list)
    until the console accepts it; `registration.json` also records `tenant` and `bound`. `device.pub` holds
    the base64 SPKI and a newline.
17. **Transport:** `Listener` gains `accept_timeout` (default: blocking accept) so the server loop can stop;
    a non-socket file at the endpoint path is refused rather than unlinked.
18. **Not implemented in core:** `moorai-guardctl` (release is reachable over IPC as an admin peer);
    Windows `running_privileged`. On Linux, `hostname` is `gethostname(2)` (the macOS call, shared in
    `platform/mod.rs`; "" on failure, so no actor is derived); the rest of the Linux platform is still `todo!()`.
19. **macOS platform:** `machine_id` is `gethostuuid(2)`, the same UUID as `IOPlatformUUID`. `hostname` is
    `gethostname(2)`, the value Node's `os.hostname()` returns, which the hook reports as `device`. `ProcInfo.uid`
    is the effective uid (`pbi_uid`), which `LOCAL_PEERCRED` also reports. `awakeSec`
    (`CLOCK_UPTIME_RAW`) can read up to a few seconds above `uptimeSec` (now − `kern.boottime`), because one clock
    is raw and the other adjusted. The difference was measured at about 10 s after 8.6 h of uptime with no sleep;
    `CLOCK_MONOTONIC_RAW` for `uptimeSec` would remove it, which would be a contract change.
20. **Hook policy through the helper** (`cli/guardd-policy.mjs`, `cli/hook-core.mjs` `loadVerifiedPolicy`
    `helper`). The hook asks the helper only when all of these hold:
    - it holds a policy key (anchored or pinned);
    - the pin is not missing;
    - the call is a network call;
    - the machine config's `helper` is not `off`.
    It uses the answer only when the hello proof verifies, the helper's tenant is the hook's, the `source` is
    `fresh`, and the body passes the same signature, tenant and rollback checks as a direct fetch. A good answer
    is written as the hook's cache and, for a real signature, as its last-known-good and mark. A body that does
    not verify is reported as the tamper pair `{source: "helper", status}`. A copy behind the hook's mark is
    dropped silently, because the hook may have fetched directly more recently. In every other case the hook takes
    the direct path. `required` mode is not enforced for the policy read yet: the hook falls back as if
    `optional`.
21. **`--bind` trust** (`guardd/packaging/macos/bind.sh`). The console URL and tenant come only from the command
    line. The install token comes from the sudo user's hook config, read as that user after an ownership walk:
    the file and every directory owned by that user or root and not group- or world-writable; a symbolic link
    only for a root-owned directory. Nothing is written before an interactive yes or `--yes`.
