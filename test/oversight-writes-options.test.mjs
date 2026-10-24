// Weakening oversight (#84): shell writes whose destination the server or the tool's own option parsing picks.
//   * A download that names its files at runtime (wget -r / -m / -i / -p / --content-disposition /
//     --trust-server-names / -x / -e / --config, curl -O with -J, curl -K, curl -o with a #N glob reference) has
//     an unknown target, judged by the existing write-target-unknown / analysis-incomplete rules.
//   * A long option is read the way the tool reads it: GNU getopt_long, git and curl 7.x accept any unique prefix
//     (`cp --target=d`, `wget --output-doc=f`, `curl --output-di d`, `git restore --pathspec-from=f`); rsync takes
//     full names only. An ambiguous or unknown option on a write tool makes the target unknown.
//   * Literal destinations the tools also write: curl --output-dir with -o, curl -D / -c / --trace / --stderr,
//     wget --default-page and a URL with no scheme or a %-escaped name, patch -r, cp --parents, git checkout
//     <tree-ish> <path> without --.
//   * A short letter GNU and BSD read with different arity (cp -S, install -S / -D / -T, sed -l) followed by more
//     letters or an option word, git's work tree moved by GIT_WORK_TREE / GIT_DIR / --git-dir, and a curl / wget
//     config picked through CURL_HOME / XDG_CONFIG_HOME / WGETRC / SYSTEM_WGETRC / HOME are unknown; git -C is
//     cumulative.
//   * git rm / git mv read git's global options as checkout / restore do (one parser): a moved work tree,
//     repository or index (GIT_INDEX_FILE too) is unknown, paths resolve under -C. Environment names match in any case.
//   * git's global options that take the next word skip it; any other option before the subcommand, a non-literal
//     word there or a command git does not have is unknown. A drive-letter or UNC path is not joined onto -C / -d.
//   * Only a builtin, spelt as git spells it, is known; a -c / --config-env / GIT_CONFIG_* key that could run a
//     command (alias.* included), a config file the environment picks, --exec-path=<dir> are unknown. Outside Windows
//     a Windows-only rooted shape under -C / -d is unknown.
//   * A pager / editor / ssh / askpass / external-diff / proxy variable outside the harmless set, GIT_COMMON_DIR,
//     GIT_TEMPLATE_DIR, GIT_OBJECT_DIRECTORY and clone --template / -c are unknown; a GIT_TRACE* path is a write; a
//     write to a git hook, a git config or the .git file, and git config setting an unsafe key, are memory-file.
//     PowerShell on POSIX gets no exception.
//   * git config reads options only before its first word, a subcommand only as the first word, a long option by a
//     unique prefix; clone / init / init-db read --template and -c / --config by unique prefix and inside a short
//     cluster; an unknown or ambiguous option on them is unknown. GIT_TRACE* naming ~ or ~/… is a write under the home
//     directory. A commondir and a worktree's gitdir are memory-file.
//
//   node --test --import ./test/hermetic-env.mjs test/oversight-writes-options.test.mjs
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { oversightCommandSignals } from "../cli/oversight-shell.mjs";
import { oversightPolicy } from "../cli/oversight-surfaces.mjs";
import { writeTargets, gitInvocation, gitConfigWrite } from "../cli/oversight-shell-writes.mjs";
import { oversightEditSignals } from "../cli/oversight-signals.mjs";
import { oversightMcpSignals } from "../cli/oversight-mcp.mjs";

const proj = mkdtempSync(join(tmpdir(), "moorai-ovopts-"));
after(() => rmSync(proj, { recursive: true, force: true }));
for (const d of ["ops/alerting", "src", ".claude/rules", "-x"]) mkdirSync(join(proj, d), { recursive: true });

const surfaces = oversightPolicy({ oversight: { v: 1, protectedPaths: ["ops/alerting/**"] } }, () => {});
const none = oversightPolicy({}, () => {});
const sh = (command) => oversightCommandSignals(command, { surfaces, cwd: proj });
const bare = (command) => oversightCommandSignals(command, { surfaces: none, cwd: proj });
const MEM = ["memory-file"], PROT = ["protected-surface"], INC = ["analysis-incomplete"];
const each = (list, expect, f = sh) => { for (const c of list) assert.deepEqual(f(c), expect, JSON.stringify(c)); };
const U = "https://x.example.com";

// ---- finding 1: the server (or a file) names what is written ----
const SERVER_NAMED = [
  `wget -r ${U}/`, `wget --recursive ${U}/docs/`, `wget -m ${U}/`, `wget --mirror ${U}/`, `wget -i urls.txt`, `wget --input-file=urls.txt`,
  `wget -qi urls.txt`, `wget -p ${U}/`, `wget --page-requisites ${U}/`, `wget --content-disposition ${U}/dl?id=1`,
  `wget --trust-server-names ${U}/latest`, `wget -x ${U}/a/b.txt`, `wget --force-directories ${U}/a/b.txt`,
  `wget -e output_document=CLAUDE.md ${U}/a`, `wget --execute=dir_prefix=.claude ${U}/a`, `wget --config=rc ${U}/a`,
  `curl -OJ ${U}/dl`, `curl -O -J ${U}/dl`, `curl --remote-name --remote-header-name ${U}/dl`, `curl -JO ${U}/dl`,
  `curl --remote-name-all -J ${U}/a ${U}/b`, `curl -K cfg.txt`, `curl --config cfg.txt ${U}/a`, `curl -o "f_#1.md" "${U}/{a,b}"`
];
test("finding 1: a download whose file names the server or a file picks is analysis-incomplete when a surface is declared", () => {
  each(SERVER_NAMED, INC);
});
test("finding 1: with no policy it is write-target-unknown (notify), the existing proportionate rule", () => {
  each(SERVER_NAMED, ["write-target-unknown"], bare);
});
test("finding 1: with -O every download goes to that one file, so nothing is unknown", () => {
  each([`wget -r -O out.html ${U}/`, `wget -i urls.txt -O all.txt`, `curl -g -o "f_#1.md" ${U}/a`], [], sh);
  each([`wget -r -O CLAUDE.md ${U}/`, `curl -J -o CLAUDE.md ${U}/dl`], MEM);
});

// ---- literal destinations the same tools write ----
test("curl --output-dir applies to -o; -D / -c / --trace / --stderr / --libcurl / --etag-save write their file", () => {
  each([`curl --output-dir ops/alerting -o rules.yaml ${U}/a`, `curl --output-dir=ops -o alerting/rules.yaml ${U}/a`], PROT);
  each([`curl -D CLAUDE.md ${U}/a`, `curl --dump-header CLAUDE.md ${U}/a`, `curl -c CLAUDE.md ${U}/a`, `curl --cookie-jar=AGENTS.md ${U}/a`,
    `curl --trace CLAUDE.md ${U}/a`, `curl --trace-ascii CLAUDE.md ${U}/a`, `curl --stderr CLAUDE.md ${U}/a`, `curl --libcurl CLAUDE.md ${U}/a`,
    `curl --etag-save CLAUDE.md ${U}/a`, `curl --hsts CLAUDE.md ${U}/a`, `curl --alt-svc CLAUDE.md ${U}/a`], MEM);
});
test("wget: a URL with no scheme, a %-escaped name and --default-page name the file wget writes", () => {
  each(["wget x.example.com/r/CLAUDE.md", `wget ${U}/r/CLAUDE%2Emd`, `wget --default-page=CLAUDE.md ${U}/`, "curl -O x.example.com/r/AGENTS.md",
    `wget --save-cookies CLAUDE.md ${U}/a`, `wget --rejected-log=CLAUDE.md ${U}/a`], MEM);
});
test("patch -r (rejects: the diff's own text), cp --parents, git checkout <tree-ish> <path> without --", () => {
  each(["patch -r CLAUDE.md a.txt fix.diff", "patch --reject-file=CLAUDE.md a.txt fix.diff", "git checkout HEAD CLAUDE.md", "git checkout CLAUDE.md",
    "git checkout HEAD~3 AGENTS.md"], MEM);
  each(["cp --parents alerting/rules.yaml ops", "cp --parents -t ops alerting/rules.yaml"], PROT);
  each(["git --work-tree=ops checkout HEAD -- alerting/rules.yaml"], INC);
});

// ---- finding 2: abbreviated long options ----
test("finding 2: an abbreviated destination option is read as the option it abbreviates", () => {
  each(["cp --target=. /tmp/x/CLAUDE.md", "cp --target-dir . /tmp/x/CLAUDE.md", "cp --t=. /tmp/x/AGENTS.md", "install --target=. /tmp/x/AGENTS.md",
    "mv --targ=. /tmp/x/CLAUDE.md", "mv --target-d . /tmp/x/CLAUDE.md", "mv --targ=.claude/rules /tmp/x/evil.md", "mv --target-d .claude/rules /tmp/x/evil.md", "cp evil CLAUDE.md --suff .bak", "rsync x CLAUDE.md --log-file /tmp/log",
    "rsync -a --temp-dir /tmp x CLAUDE.md", `wget --output-doc=CLAUDE.md ${U}/a`, `wget --output-d CLAUDE.md ${U}/a`, `wget --output-f=CLAUDE.md ${U}/a`,
    `curl --dump-h CLAUDE.md ${U}/a`, "patch --outp=CLAUDE.md a.txt fix.diff", "patch --out CLAUDE.md a.txt fix.diff",
    "sed --in-pl 's/a/b/' CLAUDE.md", "sed --i 's/a/b/' CLAUDE.md", "sed -i --expr=s/a/b/ CLAUDE.md", "sed -I '' 's/a/b/' CLAUDE.md",
    "echo x | tee -- -x/../CLAUDE.md", "echo x | tee --app CLAUDE.md", "git restore --sour HEAD CLAUDE.md", "git restore --wo CLAUDE.md"], MEM);
  each([`curl --output-di ops/alerting -O ${U}/rules.yaml`, `wget --directory-p=ops/alerting ${U}/rules.yaml`], PROT);
});
test("finding 2: a path list read from a file through an abbreviated option is unknown", () => {
  each(["git restore --pathspec-from=list.txt", "git checkout --pathspec-from=list.txt HEAD", `wget --input=urls.txt`, `wget --mirr ${U}/`,
    `wget --content-d ${U}/dl`, `curl --remote-h -O ${U}/dl`], INC);
});
test("finding 2: an ambiguous or unknown option on a write tool makes the target unknown", () => {
  each(["cp --re a.txt b.txt", "cp --frobnicate a.txt b.txt", "cp -K a.txt b.txt", "mv --frobnicate a.txt b.txt", "install --frob a.txt b.txt",
    "rsync --frobnicate a.txt b.txt", "rsync --temp-d /tmp a.txt b.txt", "rsync --verb a.txt b.txt", "curl --outp f.txt " + U, "curl --frobnicate -o f.txt " + U, `wget --no-c ${U}/a.tgz`, `wget --frob ${U}/a.tgz`,
    "patch --reject=f.txt a.txt fix.diff", "patch --frob a.txt fix.diff", "echo x | tee --frob f.txt", "sed -i --frob 's/a/b/' f.txt",
    "git restore --frob src/a.js", "git checkout --frob -- src/a.js"], INC);
  each(["cp --frobnicate a.txt b.txt", "curl --outp f.txt " + U], ["write-target-unknown"], bare);
});

test("benign: full option names, negations and common flags stay clean", () => {
  each([
    "cp -a src/ build/", "cp --recursive --preserve=mode src build", "cp --backup=numbered a.txt b.txt", "cp -c a.txt b.txt", "mv -v a.txt b.txt",
    "install -m 755 -D bin/x build/bin/x", "rsync -avz --delete --exclude=node_modules ./ host:/srv/app", "rsync --no-perms -a src/ build/",
    `curl -fsSL ${U}/install.sh -o install.sh`, `curl --compressed -H 'x: y' ${U}/a`, `curl --no-progress-meter --location ${U}/a`, `curl --no-location ${U}/a`,
    `curl -sS --retry 3 --json '{}' ${U}/a`, `wget -q ${U}/pkg.tgz`, `wget -nv -nc ${U}/pkg.tgz`, `wget --no-check-certificate ${U}/pkg.tgz`, `wget -O - ${U}/a`,
    `wget --tries=3 --timeout 10 ${U}/pkg.tgz`, "git checkout main", "git checkout -b feature/x", "git checkout -B fix origin/main", "git restore --staged src/app.js",
    "git restore --no-overlay src/app.js", "sed -i 's/a/b/' src/app.js", "sed -i.bak -e 's/a/b/' src/app.js", "sed -n '1,5p' src/app.js",
    "echo x | tee --append out.log", "echo x | tee -a out.log", "patch -p1 src/a.py fix.diff", "patch --dry-run src/a.py fix.diff"
  ], [], bare);
});

// ---- a short letter whose arity differs between GNU and BSD (cp / install -S, install -D / -T, sed -l) ----
const has = (cmd, sig, f = sh) => { const s = f(cmd); assert.ok(s.includes(sig), `${cmd}: ${JSON.stringify(s)}`); return s; };
test("arity conflict: more letters after the conflicting one in its cluster, or an option word after it, is unknown", () => {
  // Measured: GNU `cp -St x dest` / `cp -S -t x dest` / `install -St x dest` take "t" / "-t" as the backup suffix and
  // write dest; macOS `install -Dt x dest` / `install -Tt x dest` take "t" as destdir / tags and write dest.
  for (const c of ["cp -St x ops/alerting/rules.yaml", "cp -S -t x ops/alerting/rules.yaml", "install -St x ops/alerting/rules.yaml",
    "install -Dt x ops/alerting/rules.yaml", "install -Tt x ops/alerting/rules.yaml", "install -D -t x ops/alerting/rules.yaml", "install -Sm 644 x b.txt"]) has(c, "analysis-incomplete");
  for (const c of ["cp -St x ops/alerting/rules.yaml", "install -Dt x ops/alerting/rules.yaml"]) has(c, "protected-surface");
  has("sed -li 's/a/b/' CLAUDE.md", "analysis-incomplete");
  has("cp -St x CLAUDE.md", "write-target-unknown", bare);
});
test("arity conflict: the letter alone, before a plain word, keeps the destination as the last word", () => {
  each(["cp -S .bak a.txt b.txt", "install -m 644 -D a.txt build/a.txt", "install -S a.txt b.txt", "cp -pS a.txt b.txt"], [], bare);
});

// ---- git: the work tree from the environment, and -C applied cumulatively ----
test("git: GIT_WORK_TREE or GIT_DIR in the command's prefix (or after env / sudo), or --git-dir, makes the target unknown", () => {
  // Measured (git 2.39.5, 2.47.3): GIT_WORK_TREE=/x git checkout HEAD -- f writes /x/f; GIT_DIR / --git-dir naming a
  // repository whose config sets core.worktree writes there.
  each(["GIT_WORK_TREE=ops git checkout HEAD -- alerting/rules.yaml", "env GIT_WORK_TREE=ops git checkout -- alerting/rules.yaml",
    "sudo GIT_WORK_TREE=ops git restore alerting/rules.yaml", "GIT_DIR=/tmp/o/.git git restore src/a.js", "GIT_DIR=/tmp/o/.git GIT_WORK_TREE=/tmp/w git checkout -- f",
    "git --git-dir=/tmp/o/.git checkout -- src/a.js", "git --git-dir /tmp/o/.git restore src/a.js"], INC);
  each(["GIT_PAGER=cat git checkout -- src/a.js", "LC_ALL=C git restore src/a.js"], [], bare);
});
test("git: -C is cumulative (git -C a -C b is a/b; an absolute one starts over)", () => {
  each(["git -C ops -C alerting checkout -- rules.yaml", "git -C /nowhere -C " + join(proj, "ops") + " restore alerting/rules.yaml"], PROT);
});

// ---- curl / wget: a config file chosen through the environment ----
test("curl / wget: CURL_HOME / XDG_CONFIG_HOME / HOME or WGETRC / SYSTEM_WGETRC / HOME in the prefix makes the target unknown", () => {
  // Measured (curl 7.88.1, wget 1.21.3): each points the tool at a config whose output= / output_document= is obeyed.
  each([`CURL_HOME=/tmp/x curl ${U}/a`, `XDG_CONFIG_HOME=/tmp/x curl -s ${U}/a`, `HOME=/tmp/h curl ${U}/a`, `env CURL_HOME=/tmp/x curl ${U}/a`,
    `WGETRC=/tmp/rc wget ${U}/a.tgz`, `SYSTEM_WGETRC=/tmp/rc wget ${U}/a.tgz`, `HOME=/tmp/h wget -q ${U}/a.tgz`], INC);
  // curl -q (first) reads no .curlrc; wget --no-config reads no wgetrc (measured); other variables change nothing.
  each([`HOME=/tmp/h curl -q ${U}/a`, `CURL_HOME=/tmp/x curl --disable -s ${U}/a`, `WGETRC=/tmp/rc wget --no-config ${U}/a.tgz`, `LANG=C curl -s ${U}/a`, `curl -s ${U}/a`], [], bare);
});

// ---- git rm / git mv: the same global options as checkout / restore (one parser, gitInvocation) ----
test("git rm / mv: --work-tree / --git-dir / GIT_WORK_TREE / GIT_DIR / GIT_INDEX_FILE make the target unknown", () => {
  // Measured (git 2.39.5, 2.47.3, 2.54.0): GIT_WORK_TREE=/x git rm f removes /x/f; git mv g h under it moves /x/g to
  // /x/h; GIT_DIR naming a repository whose config sets core.worktree removes and moves there.
  const moved = ["git --work-tree=/tmp/w rm src/a.js", "git --work-tree /tmp/w rm -q src/a.js", "GIT_WORK_TREE=/tmp/w git rm src/a.js",
    "env GIT_WORK_TREE=/tmp/w git rm --cached src/a.js", "GIT_DIR=/tmp/o/.git git rm src/a.js", "git --git-dir=/tmp/o/.git rm src/a.js",
    "git --git-dir /tmp/o/.git mv src/a.js src/b.js", "git --work-tree=/tmp/w mv src/a.js src/b.js", "sudo GIT_WORK_TREE=/tmp/w git mv src/a.js src/b.js",
    "GIT_DIR=/tmp/o/.git git mv -k src/a.js src/b.js", "git -c x.y=z --work-tree /tmp/w rm src/a.js", "GIT_INDEX_FILE=/tmp/idx git rm --cached src/a.js",
    "GIT_INDEX_FILE=/tmp/idx git mv src/a.js src/b.js"];
  each(moved, INC);
  for (const c of ["GIT_WORK_TREE=/tmp/w git rm src/a.js", "git --work-tree /tmp/w mv src/a.js src/b.js"]) has(c, "write-target-unknown", bare);
  // A path removed by name is still judged by its name.
  has("git --work-tree=/tmp/w rm monitoring/scope.py", "wiring-removed");
  has("GIT_WORK_TREE=/tmp/w git rm monitoring/scope.py", "analysis-incomplete");
});
test("git rm / mv: -C is cumulative and the paths resolve under it", () => {
  each(["git -C ops rm alerting/rules.yaml", "git -C ops -C alerting rm rules.yaml", "git -C /nowhere -C " + join(proj, "ops") + " rm -q alerting/rules.yaml"], ["wiring-removed", "protected-surface"]);
  each(["git -C ops mv alerting/rules.yaml alerting/rules.yaml.off", "git -C ops -C alerting mv rules.yaml old.yaml", "git -C ops mv -- alerting/rules.yaml alerting/b.yaml"], PROT);
  has("git -C $D rm src/a.js", "analysis-incomplete");
});
test("git rm / mv: benign forms stay clean", () => {
  each(["git rm --cached src/a.js", "git -C src rm a.js", "git -C src mv a.js b.js", "GIT_PAGER=cat git rm src/a.js", "LC_ALL=C git mv src/a.js src/b.js",
    "git -c core.quotepath=off rm src/a.js"], [], bare);
});

// ---- environment names are matched case-insensitively (Windows reads them that way) ----
test("environment: the git, curl and wget variables match whatever their case", () => {
  each(["git_work_tree=ops git checkout -- alerting/rules.yaml", "Git_Dir=/tmp/o/.git git restore src/a.js", "env git_work_tree=/tmp/w git rm src/a.js",
    "git_index_file=/tmp/idx git checkout HEAD -- src/a.js", `curl_home=/tmp/x curl ${U}/a`, `Xdg_Config_Home=/tmp/x curl ${U}/a`, `home=/tmp/h curl ${U}/a`,
    `wgetrc=/tmp/rc wget ${U}/a.tgz`, `system_wgetrc=/tmp/rc wget ${U}/a.tgz`, `Home=/tmp/h wget ${U}/a.tgz`], INC);
  each(["git_pager=cat git checkout -- src/a.js", `lang=C curl -s ${U}/a`, `home=/tmp/h curl -q ${U}/a`, `wgetrc=/tmp/rc wget --no-config ${U}/a.tgz`], [], bare);
});

// ---- repository-selecting variables, measured one by one ----
test("git: GIT_INDEX_FILE makes the target unknown (git writes the index it names)", () => {
  // Measured (git 2.39.5, 2.47.3, 2.54.0): GIT_INDEX_FILE=idx git checkout HEAD -- f (and restore -s HEAD --staged f)
  // creates idx, resolved against the top of the work tree rather than the current directory.
  each(["GIT_INDEX_FILE=idx git checkout HEAD -- src/a.js", "GIT_INDEX_FILE=ops/alerting/x git restore -s HEAD --staged src/a.js",
    "GIT_INDEX_FILE=/tmp/idx git restore -s HEAD -SW src/a.js"], INC);
});
test("git: variables measured not to move checkout / restore / rm / mv writes stay clean", () => {
  // Measured (git 2.39.5, 2.47.3, 2.54.0), each against a/f with the command run in a: GIT_COMMON_DIR naming another
  // repository (with or without core.worktree in its config), GIT_CONFIG naming a config with core.worktree,
  // GIT_CEILING_DIRECTORIES and GIT_DISCOVERY_ACROSS_FILESYSTEM write a/f or nothing. (GIT_CONFIG_GLOBAL /
  // GIT_CONFIG_SYSTEM leave the paths alone too, but the config they name can run a command: below.)
  // (GIT_COMMON_DIR leaves the paths alone too, but runs hooks from that directory: below.)
  const vars = ["GIT_CONFIG=/tmp/cfg", "GIT_CEILING_DIRECTORIES=/tmp", "GIT_DISCOVERY_ACROSS_FILESYSTEM=1"];
  each(vars.flatMap((v) => [`${v} git checkout -- src/a.js`, `${v} git restore src/a.js`, `${v} git rm src/a.js`, `${v} git mv src/a.js src/b.js`]), [], bare);
});

// ---- git's global options: every one that takes the next word, and fail closed on anything else ----
test("git: a global option that takes the next word does not hide the subcommand", () => {
  // Measured (git 2.54.0, `git help git` OPTIONS; git 2.39.5): --attr-source, --config-env, --namespace, --git-dir,
  // --work-tree, -C and -c take the next word; 2.39.5 also --super-prefix (which checkout / rm then refuse).
  each(["git --attr-source HEAD checkout -- ops/alerting/rules.yaml", "git --config-env user.name=FOO checkout -- ops/alerting/rules.yaml",
    "git --namespace ns restore ops/alerting/rules.yaml"], PROT);
  each(["git --attr-source HEAD rm ops/alerting/rules.yaml", "git --config-env user.name=FOO rm ops/alerting/rules.yaml", "git --super-prefix x/ rm ops/alerting/rules.yaml"], ["wiring-removed", "protected-surface"]);
  has("git --attr-source HEAD mv ops/alerting/rules.yaml ops/alerting/b.yaml", "protected-surface");
});
test("git: a non-literal word before the subcommand leaves the subcommand judged (v1.34.1 caught git $OPTS rm)", () => {
  has("git $OPTS rm monitoring/scope.py", "wiring-removed");
  has("git $OPTS rm monitoring/scope.py", "analysis-incomplete");
  has("git ${G} mv monitoring/scope.py /tmp/x.py", "wiring-removed");
  has("git $OPTS checkout -- src/a.js", "analysis-incomplete");
});
test("git: an option git does not have before the subcommand, or a command git does not have, is unknown", () => {
  each(["git --bogus rm src/a.js", "git --bogus x checkout -- src/a.js", "git -Cops rm src/a.js", "git --no-pag checkout -- src/a.js",
    "git co -- ops/alerting/rules.yaml", "git $CMD -- src/a.js", "git lfs pull"], INC);
  has("git co -- src/a.js", "write-target-unknown", bare);
});
test("git: known valueless global options and known commands stay clean", () => {
  each(["git --no-pager rm src/a.js", "git -p checkout -- src/a.js", "git -P log --oneline", "git --paginate diff", "git --literal-pathspecs restore src/a.js",
    "git --no-optional-locks status", "git --git-dir=.git status", "git --exec-path", "git --version", "git -v", "git help -a", "git status",
    "git -c color.ui=never diff", "git --attr-source=HEAD diff", "git --list-cmds=main", "git --bare log"], [], bare);
});

// ---- a Windows absolute path (X:, \\host\share) is not joined onto the -C / -d base ----
test("git -C / patch -d: on Windows, a drive-letter or UNC path starts over instead of joining the base", () => {
  // Measured: pwsh 7.4.2 on Linux with git 2.34.1 passes C:x, \y and C:f to git as relative names (a/C:x/f is
  // written), as bash does: a PowerShell segment is rooted only on Windows.
  const real = Object.getOwnPropertyDescriptor(process, "platform");
  Object.defineProperty(process, "platform", { value: "win32" });
  try {
    for (const ps of [false, true]) {
      const dest = (bin, args) => writeTargets(bin, args, { ps }).writes.map((w) => w.dest);
      assert.deepEqual(dest("git", ["-C", "a", "-C", "D:/x", "checkout", "--", "f"]), ["D:/x/f"]);
      assert.deepEqual(dest("git", ["-C", "C:\\repo", "checkout", "--", "D:\\y\\f"]), ["D:\\y\\f"]);
      assert.deepEqual(dest("git", ["-C", "a", "-C", "\\\\host\\share", "restore", "f"]), ["\\\\host\\share/f"]);
      assert.deepEqual(dest("git", ["-C", "a", "checkout", "--", "C:f", "\\\\h\\s\\f"]), ["C:f", "\\\\h\\s\\f"]);
      assert.deepEqual(dest("patch", ["-d", "a", "E:/w/f.py", "fix.diff"]), ["E:/w/f.py"]);
      const g = gitInvocation(["-C", "a", "-C", "C:repo", "rm", "f"], [], { ps });
      assert.deepEqual([g.under("f"), g.under("D:/z")], ["C:repo/f", "D:/z"]);
    }
  } finally { Object.defineProperty(process, "platform", real); }
  // In PowerShell on POSIX the place is unknown, as in bash.
  if (process.platform !== "win32") {
    assert.equal(writeTargets("git", ["-C", "a", "-C", "D:/x", "checkout", "--", "f"], { ps: true }).unknown, true);
    assert.equal(writeTargets("patch", ["-d", "a", "E:/w/f.py", "fix.diff"], { ps: true }).unknown, true);
  }
});

// ---- outside Windows (PowerShell included), C:x, \x and \\host\share are relative names: whether git joins them is unknown ----
test("git -C / patch -d on POSIX: a Windows-only rooted shape under a base is unknown; / is rooted everywhere", () => {
  // Measured (git 2.39.5, 2.54.0): `git -C a -C C:x checkout -- f` writes a/C:x/f, `git -C a -C '\y' checkout -- f`
  // writes a/\y/f, `git -C a checkout -- C:f` writes a/C:f.
  if (process.platform === "win32") return;
  const wt = (bin, args) => writeTargets(bin, args);
  for (const a of [["-C", "a", "-C", "C:x", "checkout", "--", "f"], ["-C", "a", "-C", "\\y", "checkout", "--", "f"], ["-C", "a", "-C", "\\\\host\\share", "restore", "f"],
    ["-C", "a", "checkout", "--", "C:f"], ["-C", "a", "restore", "\\\\h\\s\\f"]]) assert.equal(wt("git", a).unknown, true, JSON.stringify(a));
  assert.equal(wt("patch", ["-d", "a", "E:/w/f.py", "fix.diff"]).unknown, true);
  assert.deepEqual(wt("git", ["-C", "a", "-C", "/x", "checkout", "--", "f"]), { writes: [{ dest: "/x/f", sources: null, dir: false }], unknown: false });
  assert.deepEqual(wt("git", ["-C", "C:x", "checkout", "--", "f"]).writes.map((w) => w.dest), ["C:x/f"]);
  has("git -C ops -C C:x checkout -- f", "write-target-unknown", bare);
  has("git -C ops rm C:x/rules.yaml", "analysis-incomplete");
  has("git -C ops mv alerting/rules.yaml C:x", "analysis-incomplete");
});

// ---- the subcommand in another case is not the builtin ----
test("git: a subcommand in another case is unknown, and still judged as the command it folds to", () => {
  // Measured: git 2.39.5 (Linux) runs alias.checkout for `git CHECKOUT` ("not a git command" without one); git 2.54.0
  // (macOS) runs git-core/git-CHECKOUT, which refuses ("cannot handle CHECKOUT as a builtin"). Neither runs the builtin.
  each(["git CHECKOUT -- src/a.js", "git Restore src/a.js", "git MV src/a.js src/b.js"], INC);
  has("git Rm monitoring/scope.py", "wiring-removed");
  has("git Rm monitoring/scope.py", "analysis-incomplete");
});

// ---- only a builtin is known; alias.* and keys that run a command are not ----
test("git: a command that is not a builtin on git 2.39.5, 2.47.3 and 2.54.0 is unknown", () => {
  // Measured: `git -c alias.svn='!touch x' svn` runs the alias where git-svn is not installed (2.39.5, 2.54.0), as do
  // send-email and p4 (2.39.5) and instaweb (2.54.0); an installed script command (subtree) wins over the alias.
  each(["git svn rebase", "git subtree add --prefix x y", "git send-email x.patch", "git p4 sync", "git instaweb"], INC);
});
test("git: -c / --config-env / GIT_CONFIG_* with a key that can run a command, or any alias.*, is unknown", () => {
  // Measured (git 2.39.5, 2.54.0): -c core.fsmonitor=… runs it on status, checkout and rm --cached, as do
  // GIT_CONFIG_COUNT / GIT_CONFIG_KEY_0 and GIT_CONFIG_PARAMETERS; -c core.pager=… and -c pager.log=… run on a
  // terminal; --config-env alias.zz=VAR runs the alias.
  each(["git -c core.fsmonitor='cp x CLAUDE.md' status", "git -c core.pager=x log", "git -c pager.log=x log", "git -c diff.external=x diff",
    "git -c core.hooksPath=/tmp/h checkout -- src/a.js", "git -c credential.helper=x fetch", "git --config-env core.sshCommand=E fetch",
    "git --config-env=core.editor=E commit", "git -c alias.svn='!touch pwned' svn", "git -c alias.st=status status", "git --config-env alias.rm=PW rm src/a.js",
    "git -c filter.x.smudge=y checkout -- src/a.js", "git -c Core.FSMonitor=x status", "git -c core.worktree=/tmp/w status",
    "GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.fsmonitor GIT_CONFIG_VALUE_0=x git status", "git_config_count=1 git_config_key_0=core.pager git log",
    "GIT_CONFIG_COUNT=1 git status", "GIT_CONFIG_COUNT=2 GIT_CONFIG_KEY_0=color.ui GIT_CONFIG_VALUE_0=never git status",
    "GIT_CONFIG_PARAMETERS=\"'core.fsmonitor'='x'\" git status"], INC);
});
test("git: a config file picked through the environment, or another exec path, is unknown", () => {
  // Measured (git 2.39.5, 2.54.0): a core.fsmonitor in the config named by GIT_CONFIG_GLOBAL / GIT_CONFIG_SYSTEM, or
  // found through HOME / XDG_CONFIG_HOME, runs on status and checkout (GIT_CONFIG is not read); --exec-path=d and
  // GIT_EXEC_PATH=d run a planted d/git-svn (a builtin such as checkout is not replaced).
  each(["GIT_CONFIG_GLOBAL=/tmp/cfg git status", "GIT_CONFIG_SYSTEM=/tmp/cfg git checkout -- src/a.js", "HOME=/tmp/h git status",
    "XDG_CONFIG_HOME=/tmp/x git status", "git --exec-path=/tmp/x checkout -- src/a.js", "GIT_EXEC_PATH=/tmp/x git status"], INC);
});
test("git: config keys that cannot run anything stay clean", () => {
  each(["git -c color.ui=never diff", "git -c core.quotepath=off status", "git -c user.name=a -c user.email=b commit -m x",
    "git -c advice.detachedHead=false checkout main", "git -c init.defaultBranch=main init", "git -c protocol.version=2 fetch",
    "git -c http.sslVerify=false fetch", "git -c safe.directory='*' status", "git -c log.date=iso log", "git -c commit.gpgsign=false commit -m x",
    "git -c gc.auto=0 commit -m x", "git -c core.autocrlf=false checkout main", "git --config-env=user.name=NAME commit -m x",
    "GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=color.ui GIT_CONFIG_VALUE_0=never git diff", "git --exec-path", "git --no-pager rm src/a.js", "git -p checkout -- src/a.js"], [], bare);
});

// ---- environment variables that run a command, set on a git segment ----
test("git: a pager / editor / ssh / askpass / external-diff / proxy variable with a value outside the harmless set is unknown", () => {
  // Measured (git 2.39.5, 2.54.0): GIT_PAGER / PAGER run for log and diff on a terminal, GIT_EDITOR / EDITOR for commit,
  // GIT_SSH_COMMAND / GIT_SSH / GIT_PROXY_COMMAND for fetch, GIT_EXTERNAL_DIFF for diff; none ran for checkout,
  // restore, rm, mv or status. The rule holds for every git command.
  each(["GIT_PAGER='sh x' git log", "PAGER=/tmp/p git log", "GIT_PAGER=/bin/cat git log", "GIT_PAGER='cat; sh x' git log", "git_pager='sh x' git log",
    "env GIT_PAGER='sh x' git status", "sudo PAGER='sh x' git diff", "GIT_EDITOR='code -w' git commit", "EDITOR='vim -c x' git commit", "VISUAL=emacs git commit",
    "GIT_SEQUENCE_EDITOR='sed -i x' git rebase -i HEAD~2", "GIT_SSH_COMMAND='ssh -i k' git fetch", "GIT_SSH=/tmp/s git fetch", "GIT_ASKPASS=/tmp/a git fetch",
    "SSH_ASKPASS=/tmp/a git fetch", "GIT_EXTERNAL_DIFF=/tmp/d git diff", "GIT_PROXY_COMMAND=/tmp/p git fetch", "GIT_PAGER=vim git log", "GIT_EDITOR=$E git commit"], INC);
  each(["GIT_PAGER=cat git log", "PAGER=less git log", "GIT_PAGER= git log", "GIT_PAGER=more git log", "GIT_PAGER=cat git checkout -- src/a.js",
    "GIT_EDITOR=true git commit", "GIT_EDITOR=: git commit", "EDITOR=vim git commit", "GIT_EDITOR='code --wait' git commit", "VISUAL=nano git commit",
    "GIT_SEQUENCE_EDITOR=vi git rebase -i HEAD~2", "GIT_SSH_COMMAND=true git fetch"], [], bare);
});

// ---- hooks and config run from another place ----
test("git: GIT_COMMON_DIR, GIT_TEMPLATE_DIR, GIT_OBJECT_DIRECTORY, -c core.hooksPath and clone --template / -c are unknown", () => {
  // Measured (git 2.39.5, 2.54.0): GIT_COMMON_DIR runs post-checkout / post-index-change from its hooks; GIT_TEMPLATE_DIR
  // and --template copy hooks into the new repository and clone runs post-checkout at once; clone -c / --config
  // core.hooksPath runs hooks during the clone; GIT_OBJECT_DIRECTORY receives the objects git add writes.
  each(["GIT_COMMON_DIR=/tmp/b/.git git status", "GIT_COMMON_DIR=/tmp/b/.git git checkout -- src/a.js", "git -c core.hooksPath=/tmp/h status",
    "GIT_TEMPLATE_DIR=/tmp/t git clone a b", "git clone --template=/tmp/t a b", "git init --template /tmp/t x", "git clone -c core.hooksPath=/tmp/h a b",
    "git clone --config=core.fsmonitor=x a b", "git clone --config core.pager=x a b", "GIT_OBJECT_DIRECTORY=/tmp/o git add src/a.js"], INC);
  each(["git clone https://x.example.com/r.git", "git clone -c http.sslVerify=false a b", "git init", "git init -q x"], [], bare);
});

// ---- GIT_TRACE*: a path value is a file git writes ----
test("git: GIT_TRACE* naming an absolute path is a write to it; 1 / 2 / true / 0 / a relative word are not", () => {
  // Measured (git 2.39.5, 2.54.0): GIT_TRACE=/abs/CLAUDE.md git status writes it (as do GIT_TRACE_PERFORMANCE / _SETUP /
  // _REFS / GIT_TRACE2 / _EVENT / _PERF; the others write when their trace fires); a relative value is ignored with a
  // warning; GIT_TRACE2* naming a directory writes a file of its own name inside it.
  has(`GIT_TRACE=${join(proj, "CLAUDE.md")} git status`, "memory-file", bare);
  has(`GIT_TRACE_PACKET=${join(proj, "ops/alerting/t.log")} git fetch`, "protected-surface");
  has(`git_trace=${join(proj, "CLAUDE.md")} git status`, "memory-file", bare);
  has("GIT_TRACE2_EVENT=/tmp/traces git status", "write-target-unknown", bare);
  has("GIT_TRACE=$T git status", "write-target-unknown", bare);
  each(["GIT_TRACE=1 git status", "GIT_TRACE=2 git status", "GIT_TRACE=true git status", "GIT_TRACE=0 git status", "GIT_TRACE=rel.log git status", "GIT_TRACE_PACKET=1 git fetch"], [], bare);
});

// ---- planting a hook or a config git reads ----
test("planting: a shell, Write / Edit or MCP write to a git hook, a git config or the .git file is memory-file", () => {
  // Measured (git 2.39.5, 2.54.0): a .git FILE naming another gitdir makes git read that gitdir's config (its
  // core.fsmonitor runs on status).
  each(["echo x > .git/hooks/post-checkout", "cp evil.sh .git/hooks/pre-commit", "cat > .git/config <<EOF\n[core]\nfsmonitor = x\nEOF", "echo x | tee -a .git/config",
    "echo 'gitdir: /tmp/e' > .git", "cp x sub/.git/modules/m/hooks/post-checkout", "echo x > .git/worktrees/w/config.worktree", "echo x > bare.git/hooks/update",
    "echo x >> ~/.gitconfig", "echo x > .GIT/HOOKS/pre-push"], ["memory-file"], bare);
  const w = (p, before = null) => oversightEditSignals({ path: join(proj, p), before, after: "x", surfaces: none, cwd: proj });
  assert.deepEqual(w(".git/hooks/post-checkout"), ["memory-file"]);
  assert.deepEqual(w(".git/config", "[core]\n"), ["memory-file"]);
  assert.deepEqual(oversightMcpSignals("mcp__filesystem__write_file", { path: join(proj, ".git/config"), content: "x" }, { cwd: proj, surfaces: none }), ["memory-file"]);
  // Stricter where the policy is: a protected .git is protected-surface.
  const strict = oversightPolicy({ oversight: { v: 1, protectedPaths: [".git/**"] } }, () => {});
  assert.deepEqual(oversightCommandSignals("echo x > .git/hooks/post-checkout", { surfaces: strict, cwd: proj }), ["protected-surface"]);
  assert.deepEqual(oversightCommandSignals("echo x > .git/hooks/post-checkout", { surfaces: oversightPolicy({ oversight: { v: 1, memoryFiles: "off" } }, () => {}), cwd: proj }), []);
  // Reads and ordinary files stay clean.
  each(["cat .git/config", "grep x .git/hooks/pre-commit.sample", "echo x > src/hooks/post-checkout", "echo x > docs/config"], [], bare);
});

// ---- git config arming a later command ----
test("git config: setting a key outside the safe set is memory-file; reads, unsets and safe keys stay clean", () => {
  each(["git config core.hooksPath /tmp/h", "git config --global core.fsmonitor x", "git config --system alias.co '!sh x'", "git config --local filter.x.smudge y",
    "git config --worktree core.pager x", "git config set core.hooksPath h", "git config --add alias.x y", "git config --replace-all core.editor x", "git config -e",
    "git config --edit --global", "git config edit", "git -C sub config core.fsmonitor x", "git config Core.HooksPath x", "git config $K x",
    "git config --rename-section foo core", "git config -f .git/config core.hooksPath h", "git config --file=/tmp/x.cfg include.path y"], ["memory-file"], bare);
  has(`git config -f ${join(proj, "CLAUDE.md")} user.name x`, "memory-file", bare);
  each(["git config --get core.hooksPath", "git config --list", "git config -l", "git config core.hooksPath", "git config get core.hooksPath",
    "git config list --show-origin", "git config --get-regexp alias", "git config user.name x", "git config --global user.email x", "git config --unset core.hooksPath",
    "git config pull.rebase false", "git config --global init.defaultBranch main", "git config unset alias.x",
    "git config --get-urlmatch http.proxy https://x.example.com", "git config --get core.pager less", "git config get --url=https://x.example.com http.proxy"], [], bare);
});

// ---- v1.34.3: git config reads options only before its first word ----
test("git config: a word after the key is a value, never an option (git stops at the first non-option)", () => {
  // Measured (git 2.39.5 and 2.54.0): `git config core.pager --get-x` sets core.pager to "--get-x"; `alias.x --get`,
  // `core.fsmonitor --list` / `-l` / `--unset` / `--global` each set the key to that word; `core.fsmonitor x --get`
  // sets it with the value pattern "--get"; `set core.fsmonitor --list` (2.54.0) sets it to "--list".
  each(["git config core.pager --get-x", "git config alias.x --get", "git config alias.x '--get'", "git config core.fsmonitor --list",
    "git config core.fsmonitor -l", "git config core.fsmonitor --unset", "git config core.fsmonitor --global", "git config core.fsmonitor x --get",
    "git config core.fsmonitor -- --list", "git config set core.fsmonitor --list", "git config --add core.pager --get", "git config core.fsmonitor -e"], MEM, bare);
  each(["git config --get-regexp alias x", "git config --unset core.pager x", "git config --global --get core.pager", "git config user.name --list",
    "git config get core.pager --list"], [], bare);
});

// ---- v1.34.3: abbreviated long options on git config / clone / init ----
test("git config: an abbreviated long option is the option it is a unique prefix of; an unknown or ambiguous one is unknown", () => {
  // Measured (2.39.5 and 2.54.0): --fil=f writes f, --glob writes ~/.gitconfig, --typ takes the next word; 2.54.0:
  // --comm takes the next word as the comment (`--comm user.name core.fsmonitor x` sets core.fsmonitor).
  each(["git config --comm user.name core.fsmonitor x", "git config set --comm user.name core.fsmonitor x"], MEM, bare);
  has(`git config --fil=${join(proj, "CLAUDE.md")} user.name x`, "memory-file", bare);
  has(`git config set --fil=${join(proj, "CLAUDE.md")} user.name x`, "memory-file", bare);
  has(`git config -zf${join(proj, "CLAUDE.md")} user.name x`, "memory-file", bare);
  assert.deepEqual(gitConfigWrite(["--glob", "core.fsmonitor", "x"]), { key: "core.fsmonitor", scope: "global", file: null });
  assert.deepEqual(gitConfigWrite(["--wor", "--no-wor", "core.fsmonitor", "x"]), { key: "core.fsmonitor", scope: "local", file: null });
  assert.deepEqual(gitConfigWrite(["-f", "a.cfg", "--no-file", "core.fsmonitor", "x"]), { key: "core.fsmonitor", scope: "local", file: null });
  each(["git config --typ bool user.name true", "git config -t bool user.name true", "git config --def x --get core.pager"], [], bare);
  each(["git config --bogus core.fsmonitor x", "git config --fi=a.cfg user.name x", "git config -x user.name y", "git config set --bogus user.name x"], ["write-target-unknown"], bare);
});
test("git clone / init: an abbreviated --template / --config and a -c in a short cluster are read; an unknown option is unknown", () => {
  // Measured (2.39.5 and 2.54.0): clone --templ=d / --temp d copy d's hooks and run post-checkout; clone --conf / --co
  // core.hooksPath=h, -qc core.hooksPath=h and -qccore.hooksPath=h run h's post-checkout; init --templ=d / --t d copy
  // d's hooks; clone --t is ambiguous (template, tags) and --bogus unknown (git refuses both).
  each(["git clone --templ=/tmp/t a b", "git clone --temp /tmp/t a b", "git clone a b --templ=/tmp/t", "git clone --conf core.hooksPath=/tmp/h a b",
    "git clone --co core.hooksPath=/tmp/h a b", "git clone -qc core.hooksPath=/tmp/h a b", "git clone -qccore.hooksPath=/tmp/h a b",
    "git init --templ=/tmp/t x", "git init --t /tmp/t x", "git init-db --templ=/tmp/t x", "git clone --t=/tmp/t a b", "git clone --bogus a b", "git init --bogus x"], INC);
  each(["git clone -b main a b", "git clone --depth 1 a b", "git clone -b --template a b", "git clone -qc http.sslVerify=false a b", "git init -qb main x",
    "git clone --no-template a b", "git clone -- --template=/tmp/t d", "git clone --recursive a b", "git init --shared=group x"], [], bare);
});

// ---- v1.34.3: GIT_TRACE* naming ~/… ----
test("git: GIT_TRACE* naming ~ or ~/… is a write under the home directory; ~user/… is unknown", () => {
  // Measured: bash 5.3.15 / 5.2.15 / 3.2.57, zsh 5.9 and dash expand ~/ after = in an assignment word before a command
  // (`GIT_TRACE=~/CLAUDE.md git status` writes $HOME/CLAUDE.md); ~root/… expands to root's home.
  has("GIT_TRACE=~/CLAUDE.md git status", "memory-file", bare);
  has("GIT_TRACE_PERFORMANCE=~/.claude/CLAUDE.md git status", "memory-file", bare);
  has("GIT_TRACE2_EVENT=~/traces git status", "write-target-unknown", bare);
  has("GIT_TRACE=~root/CLAUDE.md git status", "write-target-unknown", bare);
});

// ---- v1.34.3: gitdir redirect files ----
test("planting: a commondir or a worktree's gitdir is memory-file; alternates and a submodule's gitdir are not", () => {
  // Measured (2.39.5 and 2.54.0): a commondir naming another directory (.git/commondir, .git/worktrees/<w>/commondir,
  // .git/modules/<m>/commondir) makes git read that directory's config (core.fsmonitor runs) and hooks
  // (post-index-change runs); .git/worktrees/<w>/gitdir names the worktree, and `git worktree repair` then writes a .git
  // file there. objects/info/alternates, .git/gitdir, .git/modules/<m>/gitdir and info/ files run nothing.
  each(["echo /tmp/e > .git/commondir", "echo /tmp/e > .git/worktrees/w/commondir", "echo /tmp/e > .git/modules/m/commondir", "echo /tmp/e > bare.git/commondir",
    "echo /tmp/e/.git > .git/worktrees/w/gitdir", "echo x > .git/modules/m/worktrees/w/commondir"], MEM, bare);
  assert.deepEqual(oversightEditSignals({ path: join(proj, ".git/commondir"), before: null, after: "/tmp/e", surfaces: none, cwd: proj }), ["memory-file"]);
  each(["echo x > .git/objects/info/alternates", "echo x > .git/modules/m/gitdir", "echo x > .git/gitdir", "echo x > docs/commondir", "echo x > .git/info/attributes"], [], bare);
});
