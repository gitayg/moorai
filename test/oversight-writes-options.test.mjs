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
//
//   node --test --import ./test/hermetic-env.mjs test/oversight-writes-options.test.mjs
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { oversightCommandSignals } from "../cli/oversight-shell.mjs";
import { oversightPolicy } from "../cli/oversight-surfaces.mjs";

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
  each(["git --work-tree=ops checkout HEAD -- alerting/rules.yaml", "git -c core.worktree=ops checkout HEAD -- alerting/rules.yaml"], INC);
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
