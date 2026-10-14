// The Windows ancestry walk for AI_CLI_PARENT (cli/ai-cli-parents.mjs), run in the background.
//
// WHY. Windows has no cheap way to read another process's parent: the walk is Win32_Process queries through
// one PowerShell, and PowerShell start-up is measured in seconds on a loaded machine. MEASURED on GitHub's
// windows-latest runners (windows-js run 38485916629, v1.15.3): every first hook call of a session spent the
// walk's whole 8 s timeout, and a keep-alive connection the hook had opened to the console went stale while
// it waited (Node's http server closes an idle socket after 5 s), so that call's first alert POST failed with
// ECONNRESET and was lost. A hook decision must never wait on that, so on Windows the hook never walks.
//
// HOW. The first call of a session that finds no cached class starts ONE detached PowerShell (winWalkScript)
// and leaves a request: the call's own parent pid. The PowerShell warms WMI, then polls for requests for
// WALK_LIFE_MS. Every later call of the session leaves its own parent pid as early as it can (the shell an
// agent runs its hook command in lives only as long as that call, so a walk must start while a call runs),
// and the first walk that reads past that pid is written as the result. The call that finds the result
// classifies it, caches it and alerts, as a synchronous walk would.
//
// Requests and results are small files next to the session cache, in the user's state directory: the same
// trust as that cache (see the LIMIT in cli/ai-cli-parents.mjs).
import { readFileSync, writeFileSync, renameSync, mkdirSync, unlinkSync, readdirSync, statSync } from "node:fs";
import { spawn } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { systemTool } from "./machine-dir.mjs";

export const WALK_LIFE_MS = 30000; // how long one background PowerShell waits for a request
const POLL_MS = 40;
const PREFIX = "ai-cli-parents-walk-";
export const walkPaths = (dir, k) => ({ req: join(dir, `${PREFIX}${k}.req`), res: join(dir, `${PREFIX}${k}.res`) });

const psq = (s) => `'${String(s).replace(/'/g, "''")}'`;
// The background walker: the lines it writes are cli/ai-cli-parents.mjs parseWinChain's input
// ("pid|ppid|name|path|created", from the requested pid upward). A walk that reads fewer than two
// processes (the requesting call's shell already gone) is dropped and the walker waits for the next request.
// It exits after one result, after lifeMs, or as soon as the state directory is gone.
export function winWalkScript({ req, res, dir, maxLen, lifeMs = WALK_LIFE_MS, pollMs = POLL_MS }) {
  return [
    "$ErrorActionPreference='SilentlyContinue'",
    `$req=${psq(req)}; $res=${psq(res)}; $dir=${psq(dir)}`,
    `$end=[DateTime]::UtcNow.AddMilliseconds(${Number(lifeMs) | 0})`,
    "function Walk([int]$p){",
    "$o=New-Object System.Collections.Generic.List[string]",
    `for($i=0;$i -lt ${Number(maxLen) | 0};$i++){`,
    "$x=Get-CimInstance -ClassName Win32_Process -Filter \"ProcessId=$p\" -Property ProcessId,ParentProcessId,Name,ExecutablePath,CreationDate",
    "if(-not $x){break}",
    "$t=0; if($x.CreationDate){$t=$x.CreationDate.ToFileTimeUtc()}",
    "$o.Add(('{0}|{1}|{2}|{3}|{4}' -f $x.ProcessId,$x.ParentProcessId,$x.Name,$x.ExecutablePath,$t))",
    "if($x.ParentProcessId -le 4){break}",
    "$p=$x.ParentProcessId}",
    "return ,$o}",
    "$null=Get-CimInstance -ClassName Win32_Process -Filter \"ProcessId=$PID\" -Property ProcessId",
    "while(([DateTime]::UtcNow -lt $end) -and (Test-Path -LiteralPath $dir)){",
    "$p=0",
    "if(Test-Path -LiteralPath $req){$s=[IO.File]::ReadAllText($req); Remove-Item -LiteralPath $req -Force; [void][int]::TryParse($s.Trim(),[ref]$p)}",
    "if($p -gt 0){$o=Walk $p; if($o.Count -ge 2){$tmp=$res+'.tmp'; [IO.File]::WriteAllText($tmp,($o -join \"`n\")); if(Test-Path -LiteralPath $res){[IO.File]::Delete($res)}; [IO.File]::Move($tmp,$res); break}}",
    `Start-Sleep -Milliseconds ${Number(pollMs) | 0}}`
  ].join("\n");
}

function launchPowerShell(script) {
  const c = spawn(systemTool("WindowsPowerShell\\v1.0\\powershell.exe"), ["-NoProfile", "-NonInteractive", "-NoLogo", "-EncodedCommand", Buffer.from(script, "utf16le").toString("base64")],
    { detached: true, stdio: "ignore", windowsHide: true, cwd: tmpdir() });
  c.on("error", () => {});
  c.unref();
}

// Request and result files a finished or abandoned session left behind.
function sweep(dir, now) {
  try {
    for (const f of readdirSync(dir)) {
      if (!f.startsWith(PREFIX)) continue;
      const p = join(dir, f);
      try { if (now - statSync(p).mtimeMs > 2 * WALK_LIFE_MS) unlinkSync(p); } catch { /* raced */ }
    }
  } catch { /* no state directory yet */ }
}

// → { take(k) → result text | null, ask(k, pid), start(k, pid) }. Never throws, never waits.
export function windowsWalker({ stateDir, maxLen, launch = launchPowerShell, now = () => Date.now() }) {
  const w = {
    take(k) {
      const { res } = walkPaths(stateDir, k);
      let text;
      try { text = readFileSync(res, "utf8"); } catch { return null; }
      try { unlinkSync(res); } catch { /* the cache entry written next makes it moot */ }
      return text;
    },
    ask(k, pid) {
      try {
        const { req } = walkPaths(stateDir, k);
        mkdirSync(stateDir, { recursive: true });
        const tmp = `${req}.${process.pid}.tmp`;
        writeFileSync(tmp, String(Number(pid) | 0), { mode: 0o600 });
        renameSync(tmp, req);
      } catch { /* the next call asks again */ }
    },
    start(k, pid) {
      sweep(stateDir, now());
      w.ask(k, pid);
      const { req, res } = walkPaths(stateDir, k);
      try { launch(winWalkScript({ req, res, dir: stateDir, maxLen })); } catch { /* the next call after WALK_LIFE_MS starts another */ }
    }
  };
  return w;
}
