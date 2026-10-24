// The options of the shell write tools that cli/oversight-shell-writes.mjs and cli/oversight-shell.mjs read, for
// data/shell-parse.js scanArgs: all — every long option (an abbreviation resolves against it, as GNU getopt_long
// and curl / git do); valued — the long options that take the next word as their value; short — every short
// letter; shortValued — the letters that take a value. An option outside these lists makes the write target
// unknown. Each list is the union of the tools' own help output, as measured:
//   * GNU coreutils 9.1 (Debian bookworm) and 9.7 (Debian trixie): `cp --help`, `mv --help`, `install --help`,
//     `tee --help`; GNU sed 4.9 `sed --help`; GNU patch 2.7.6 `patch --help`; git 2.39.5 and 2.47.3
//     `git checkout -h`, `git restore -h`; GNU Wget 1.21.3 and 1.25.0 `wget --help`; curl 7.88.1, 8.7.1 (macOS)
//     and 8.14.1 `curl --help all`; rsync 3.4.4 `rsync --help`;
//   * the macOS (BSD) letters, from its man pages: cp -c -N -X, mv -h, install -B -f -h -l -M -T -U, sed -a -H -I
//     -l, patch -C -x (--check, --debug).
// A letter whose value differs between GNU and BSD (shortConflict) — cp -S (GNU `cp --help` "-S, --suffix=SUFFIX";
// macOS cp(1) "-S Do not attempt to preserve holes"), install -S (GNU "--suffix=SUFFIX"; macOS install(1) "-S Flush
// each file to disk"), install -D (GNU "create all leading components of DEST", no value; macOS "-D destdir"),
// install -T (GNU "--no-target-directory"; macOS "-T tags"), sed -l (GNU "-l N"; macOS "-l Make output line
// buffered") — is read as taking none when it ends its cluster before a plain word: that word is then one more
// source or file, so the destination stays the last word (and install -T leaves the caller to decide whether it is
// a directory). Followed by more letters of its cluster or by an option word it has no single reading (measured:
// GNU `cp -St x dest` and `cp -S -t x dest` take "t" / "-t" as the suffix and write dest; macOS `install -Dt x dest`
// writes dest), and the write target is unknown. sed -i (GNU: an attached suffix only; macOS: a required one, a
// word of its own) is read by the caller. mv, tee, patch and the single-implementation tools (curl, wget, rsync,
// git) have no such letter: BSD mv has no -S / -t, and every letter BSD patch shares with GNU patch has the same
// arity (macOS patch(1), GNU `patch --help`).
const opts = (all, valued, short, shortValued, more = {}) => Object.freeze({ longAll: all, longValued: valued, shortAll: short, shortValued, ...more });

export const CP = opts([
  "--archive", "--attributes-only", "--backup", "--context", "--copy-contents", "--debug", "--dereference", "--force", "--help",
  "--interactive", "--keep-directory-symlink", "--link", "--no-clobber", "--no-dereference", "--no-preserve", "--no-target-directory",
  "--one-file-system", "--parents", "--preserve", "--recursive", "--reflink", "--remove-destination", "--sparse",
  "--strip-trailing-slashes", "--suffix", "--symbolic-link", "--target-directory", "--update", "--verbose", "--version"
], ["--no-preserve", "--sparse", "--suffix", "--target-directory"], "abcdfHilLNnPpRrSstTuvXxZ", "t", { shortConflict: "S" });
export const MV = opts([
  "--backup", "--context", "--debug", "--exchange", "--force", "--help", "--interactive", "--no-clobber", "--no-copy",
  "--no-target-directory", "--strip-trailing-slashes", "--suffix", "--target-directory", "--update", "--verbose", "--version"
], ["--suffix", "--target-directory"], "bfhinStTuvZ", "St");
export const INSTALL = opts([
  "--backup", "--compare", "--context", "--debug", "--directory", "--group", "--help", "--mode", "--no-target-directory", "--owner",
  "--preserve-context", "--preserve-timestamps", "--strip", "--strip-program", "--suffix", "--target-directory", "--verbose", "--version"
], ["--group", "--mode", "--owner", "--strip-program", "--suffix", "--target-directory"], "BbCcDdfghlMmopSsTtUvZ", "BfghlMmot", { shortConflict: "DST" });
export const TEE = opts(["--append", "--help", "--ignore-interrupts", "--output-error", "--version"], [], "aip", "");
// sed: -i / -I (in place) are read by the caller: GNU takes an attached suffix only, BSD a required one.
export const SED = opts([
  "--debug", "--expression", "--file", "--follow-symlinks", "--help", "--in-place", "--line-length", "--null-data", "--posix",
  "--quiet", "--regexp-extended", "--sandbox", "--separate", "--silent", "--unbuffered", "--version"
], ["--expression", "--file", "--line-length"], "aEefHIilnrsuz", "ef");
export const PATCH = opts([
  "--backup", "--backup-if-mismatch", "--basename-prefix", "--batch", "--binary", "--check", "--context", "--debug", "--directory",
  "--dry-run", "--ed", "--force", "--forward", "--fuzz", "--get", "--help", "--ifdef", "--ignore-whitespace", "--input", "--merge",
  "--no-backup-if-mismatch", "--normal", "--output", "--posix", "--prefix", "--quiet", "--quoting-style", "--read-only",
  "--reject-file", "--reject-format", "--remove-empty-files", "--reverse", "--set-time", "--set-utc", "--silent", "--strip",
  "--suffix", "--unified", "--verbose", "--version", "--version-control"
], ["--basename-prefix", "--debug", "--directory", "--fuzz", "--get", "--ifdef", "--input", "--output", "--prefix", "--quoting-style",
  "--read-only", "--reject-file", "--reject-format", "--strip", "--suffix", "--version-control"], "BbCcDdEeFfgilNnoprRstTuVvxYZz", "BDdFgioprVxYz");
// git: every option also has a --no- form (`git restore -h`: "--[no-]source").
export const GIT_RESTORE = opts([
  "--conflict", "--ignore-skip-worktree-bits", "--ignore-unmerged", "--merge", "--ours", "--overlay", "--patch", "--pathspec-file-nul",
  "--pathspec-from-file", "--progress", "--quiet", "--recurse-submodules", "--source", "--staged", "--theirs", "--worktree"
], ["--conflict", "--pathspec-from-file", "--source"], "23mpqSsW", "s", { negatable: true });
export const GIT_CHECKOUT = opts([
  "--conflict", "--detach", "--force", "--guess", "--ignore-other-worktrees", "--ignore-skip-worktree-bits", "--merge", "--orphan",
  "--ours", "--overlay", "--overwrite-ignore", "--patch", "--pathspec-file-nul", "--pathspec-from-file", "--progress", "--quiet",
  "--recurse-submodules", "--theirs", "--track"
], ["--conflict", "--orphan", "--pathspec-from-file"], "23Bbdflmpqt", "Bb", { negatable: true });
// curl, wget and rsync also take --no-<option> for a boolean option. rsync (popt) takes no abbreviation: measured,
// rsync 3.4.4 answers `--temp-d` and `--verb` with "unknown option" (so one is unknown here too); curl 7.88.1
// takes a unique prefix (`--dump-h`) and 8.7.1 does not, so the prefix is read (a write it may make is judged).
export const CURL = opts([
  "--abstract-unix-socket", "--alt-svc", "--anyauth", "--append", "--aws-sigv4", "--basic", "--ca-native",
  "--cacert", "--capath", "--cert", "--cert-status", "--cert-type", "--ciphers", "--compressed", "--compressed-ssh",
  "--config", "--connect-timeout", "--connect-to", "--continue-at", "--cookie", "--cookie-jar", "--create-dirs",
  "--create-file-mode", "--crlf", "--crlfile", "--curves", "--data", "--data-ascii", "--data-binary", "--data-raw",
  "--data-urlencode", "--delegation", "--digest", "--disable", "--disable-eprt", "--disable-epsv",
  "--disallow-username-in-url", "--dns-interface", "--dns-ipv4-addr", "--dns-ipv6-addr", "--dns-servers",
  "--doh-cert-status", "--doh-insecure", "--doh-url", "--dump-ca-embed", "--dump-header", "--ech", "--egd-file",
  "--engine", "--etag-compare", "--etag-save", "--expect100-timeout", "--fail", "--fail-early", "--fail-with-body",
  "--false-start", "--form", "--form-escape", "--form-string", "--ftp-account", "--ftp-alternative-to-user",
  "--ftp-create-dirs", "--ftp-method", "--ftp-pasv", "--ftp-port", "--ftp-pret", "--ftp-skip-pasv-ip",
  "--ftp-ssl-ccc", "--ftp-ssl-ccc-mode", "--ftp-ssl-control", "--get", "--globoff", "--happy-eyeballs-timeout-ms",
  "--haproxy-clientip", "--haproxy-protocol", "--head", "--header", "--help", "--hostpubmd5", "--hostpubsha256",
  "--hsts", "--http0.9", "--http1.0", "--http1.1", "--http2", "--http2-prior-knowledge", "--http3", "--http3-only",
  "--ignore-content-length", "--include", "--insecure", "--interface", "--ip-tos", "--ipfs-gateway", "--ipv4",
  "--ipv6", "--json", "--junk-session-cookies", "--keepalive-cnt", "--keepalive-time", "--key", "--key-type",
  "--krb", "--libcurl", "--limit-rate", "--list-only", "--local-port", "--location", "--location-trusted",
  "--login-options", "--mail-auth", "--mail-from", "--mail-rcpt", "--mail-rcpt-allowfails", "--manual",
  "--max-filesize", "--max-redirs", "--max-time", "--metalink", "--mptcp", "--negotiate", "--netrc", "--netrc-file",
  "--netrc-optional", "--next", "--no-alpn", "--no-buffer", "--no-clobber", "--no-keepalive", "--no-npn",
  "--no-progress-meter", "--no-sessionid", "--noproxy", "--ntlm", "--ntlm-wb", "--oauth2-bearer", "--output",
  "--output-dir", "--parallel", "--parallel-immediate", "--parallel-max", "--pass", "--path-as-is", "--pinnedpubkey",
  "--post301", "--post302", "--post303", "--preproxy", "--progress-bar", "--proto", "--proto-default",
  "--proto-redir", "--proxy", "--proxy-anyauth", "--proxy-basic", "--proxy-ca-native", "--proxy-cacert",
  "--proxy-capath", "--proxy-cert", "--proxy-cert-type", "--proxy-ciphers", "--proxy-crlfile", "--proxy-digest",
  "--proxy-header", "--proxy-http2", "--proxy-insecure", "--proxy-key", "--proxy-key-type", "--proxy-negotiate",
  "--proxy-ntlm", "--proxy-pass", "--proxy-pinnedpubkey", "--proxy-service-name", "--proxy-ssl-allow-beast",
  "--proxy-ssl-auto-client-cert", "--proxy-tls13-ciphers", "--proxy-tlsauthtype", "--proxy-tlspassword",
  "--proxy-tlsuser", "--proxy-tlsv1", "--proxy-user", "--proxy1.0", "--proxytunnel", "--pubkey", "--quote",
  "--random-file", "--range", "--rate", "--raw", "--referer", "--remote-header-name", "--remote-name",
  "--remote-name-all", "--remote-time", "--remove-on-error", "--request", "--request-target", "--resolve", "--retry",
  "--retry-all-errors", "--retry-connrefused", "--retry-delay", "--retry-max-time", "--sasl-authzid", "--sasl-ir",
  "--service-name", "--show-error", "--show-headers", "--sigalgs", "--silent", "--skip-existing", "--socks4",
  "--socks4a", "--socks5", "--socks5-basic", "--socks5-gssapi", "--socks5-gssapi-nec", "--socks5-gssapi-service",
  "--socks5-hostname", "--speed-limit", "--speed-time", "--ssl", "--ssl-allow-beast", "--ssl-auto-client-cert",
  "--ssl-no-revoke", "--ssl-reqd", "--ssl-revoke-best-effort", "--ssl-sessions", "--sslv2", "--sslv3", "--stderr",
  "--styled-output", "--suppress-connect-headers", "--tcp-fastopen", "--tcp-nodelay", "--telnet-option",
  "--tftp-blksize", "--tftp-no-options", "--time-cond", "--tls-earlydata", "--tls-max", "--tls13-ciphers",
  "--tlsauthtype", "--tlspassword", "--tlsuser", "--tlsv1", "--tlsv1.0", "--tlsv1.1", "--tlsv1.2", "--tlsv1.3",
  "--tr-encoding", "--trace", "--trace-ascii", "--trace-config", "--trace-ids", "--trace-time", "--unix-socket",
  "--upload-file", "--upload-flags", "--url", "--url-query", "--use-ascii", "--user", "--user-agent", "--variable",
  "--verbose", "--version", "--vlan-priority", "--write-out", "--xattr"
], [
  "--abstract-unix-socket", "--alt-svc", "--aws-sigv4", "--cacert", "--capath", "--cert", "--cert-type", "--ciphers",
  "--config", "--connect-timeout", "--connect-to", "--continue-at", "--cookie", "--cookie-jar", "--create-file-mode",
  "--crlfile", "--curves", "--data", "--data-ascii", "--data-binary", "--data-raw", "--data-urlencode",
  "--delegation", "--dns-interface", "--dns-ipv4-addr", "--dns-ipv6-addr", "--dns-servers", "--doh-url",
  "--dump-header", "--ech", "--egd-file", "--engine", "--etag-compare", "--etag-save", "--expect100-timeout",
  "--form", "--form-string", "--ftp-account", "--ftp-alternative-to-user", "--ftp-method", "--ftp-port",
  "--ftp-ssl-ccc-mode", "--happy-eyeballs-timeout-ms", "--haproxy-clientip", "--header", "--hostpubmd5",
  "--hostpubsha256", "--hsts", "--interface", "--ip-tos", "--ipfs-gateway", "--json", "--keepalive-cnt",
  "--keepalive-time", "--key", "--key-type", "--krb", "--libcurl", "--limit-rate", "--local-port", "--login-options",
  "--mail-auth", "--mail-from", "--mail-rcpt", "--max-filesize", "--max-redirs", "--max-time", "--netrc-file",
  "--noproxy", "--oauth2-bearer", "--output", "--output-dir", "--parallel-max", "--pass", "--pinnedpubkey",
  "--preproxy", "--proto", "--proto-default", "--proto-redir", "--proxy", "--proxy-cacert", "--proxy-capath",
  "--proxy-cert", "--proxy-cert-type", "--proxy-ciphers", "--proxy-crlfile", "--proxy-header", "--proxy-key",
  "--proxy-key-type", "--proxy-pass", "--proxy-pinnedpubkey", "--proxy-service-name", "--proxy-tls13-ciphers",
  "--proxy-tlsauthtype", "--proxy-tlspassword", "--proxy-tlsuser", "--proxy-user", "--proxy1.0", "--pubkey",
  "--quote", "--random-file", "--range", "--rate", "--referer", "--request", "--request-target", "--resolve",
  "--retry", "--retry-delay", "--retry-max-time", "--sasl-authzid", "--service-name", "--sigalgs", "--socks4",
  "--socks4a", "--socks5", "--socks5-gssapi-service", "--socks5-hostname", "--speed-limit", "--speed-time",
  "--ssl-sessions", "--stderr", "--telnet-option", "--tftp-blksize", "--time-cond", "--tls-max", "--tls13-ciphers",
  "--tlsauthtype", "--tlspassword", "--tlsuser", "--trace", "--trace-ascii", "--trace-config", "--unix-socket",
  "--upload-file", "--upload-flags", "--url", "--url-query", "--user", "--user-agent", "--variable",
  "--vlan-priority", "--write-out"
], "#0123456:ABCDEFGHIJKLMNOPQRSTUVXYZabcdefghijklmnopqrstuvwxyz", "ACDEFHKPQTUXYbcdehmortuwxyz", { negatable: true });
// wget: -nv / -nc / -nH / -nd / -np are -n with a value.
export const WGET = opts([
  "--accept", "--accept-regex", "--adjust-extension", "--append-output", "--ask-password", "--auth-no-challenge",
  "--background", "--backup-converted", "--backups", "--base", "--bind-address", "--body-data", "--body-file",
  "--ca-certificate", "--ca-directory", "--certificate", "--certificate-type", "--ciphers", "--compression",
  "--config", "--connect-timeout", "--content-disposition", "--content-on-error", "--continue",
  "--convert-file-only", "--convert-links", "--crl-file", "--cut-dirs", "--debug", "--default-page",
  "--delete-after", "--directory-prefix", "--dns-timeout", "--domains", "--exclude-directories", "--exclude-domains",
  "--execute", "--follow-ftp", "--follow-tags", "--force-directories", "--force-html", "--ftp-password",
  "--ftp-user", "--ftps-clear-data-connection", "--ftps-fallback-to-ftp", "--ftps-implicit", "--ftps-resume-ssl",
  "--header", "--help", "--hsts-file", "--http-password", "--http-user", "--https-only", "--ignore-case",
  "--ignore-length", "--ignore-tags", "--include-directories", "--inet4-only", "--inet6-only", "--input-file",
  "--keep-session-cookies", "--level", "--limit-rate", "--load-cookies", "--local-encoding", "--max-redirect",
  "--method", "--mirror", "--no-cache", "--no-check-certificate", "--no-clobber", "--no-config", "--no-cookies",
  "--no-directories", "--no-dns-cache", "--no-glob", "--no-host-directories", "--no-hsts", "--no-http-keep-alive",
  "--no-if-modified-since", "--no-iri", "--no-netrc", "--no-parent", "--no-passive-ftp", "--no-proxy",
  "--no-remove-listing", "--no-use-server-timestamps", "--no-verbose", "--no-warc-compression", "--no-warc-digests",
  "--no-warc-keep-log", "--output-document", "--output-file", "--page-requisites", "--password", "--pinnedpubkey",
  "--post-data", "--post-file", "--prefer-family", "--preserve-permissions", "--private-key", "--private-key-type",
  "--progress", "--protocol-directories", "--proxy-password", "--proxy-user", "--quiet", "--quota", "--random-wait",
  "--read-timeout", "--recursive", "--referer", "--regex-type", "--reject", "--reject-regex", "--rejected-log",
  "--relative", "--remote-encoding", "--report-speed", "--restrict-file-names", "--retr-symlinks",
  "--retry-connrefused", "--retry-on-host-error", "--retry-on-http-error", "--save-cookies", "--save-headers",
  "--secure-protocol", "--server-response", "--show-progress", "--span-hosts", "--spider", "--start-pos",
  "--strict-comments", "--timeout", "--timestamping", "--tries", "--trust-server-names", "--unlink", "--use-askpass",
  "--user", "--user-agent", "--verbose", "--version", "--wait", "--waitretry", "--warc-cdx", "--warc-dedup",
  "--warc-file", "--warc-header", "--warc-max-size", "--warc-tempdir", "--xattr"
], [
  "--accept", "--accept-regex", "--append-output", "--backups", "--base", "--bind-address", "--body-data",
  "--body-file", "--ca-certificate", "--ca-directory", "--certificate", "--certificate-type", "--ciphers",
  "--compression", "--config", "--connect-timeout", "--crl-file", "--cut-dirs", "--default-page",
  "--directory-prefix", "--dns-timeout", "--domains", "--exclude-directories", "--exclude-domains", "--execute",
  "--follow-tags", "--ftp-password", "--ftp-user", "--header", "--http-password", "--http-user", "--ignore-tags",
  "--include-directories", "--input-file", "--level", "--limit-rate", "--load-cookies", "--local-encoding",
  "--method", "--output-document", "--output-file", "--password", "--pinnedpubkey", "--post-data", "--post-file",
  "--prefer-family", "--private-key", "--private-key-type", "--progress", "--proxy-password", "--proxy-user",
  "--quota", "--read-timeout", "--referer", "--regex-type", "--reject", "--reject-regex", "--rejected-log",
  "--remote-encoding", "--report-speed", "--restrict-file-names", "--retry-on-http-error", "--save-cookies",
  "--secure-protocol", "--start-pos", "--timeout", "--tries", "--use-askpass", "--user", "--user-agent", "--wait",
  "--waitretry", "--warc-dedup", "--warc-file", "--warc-header", "--warc-max-size", "--warc-tempdir"
], "46ABDEFHIKLNOPQRSTUVXabcdehiklmnopqrtvwx", "ABDIOPQRTUXaeilnotw", { negatable: true });
export const RSYNC = opts([
  "--8-bit-output", "--acls", "--address", "--append", "--append-verify", "--archive", "--atimes", "--backup",
  "--backup-dir", "--block-size", "--blocking-io", "--bwlimit", "--checksum", "--checksum-choice", "--checksum-seed",
  "--chmod", "--chown", "--compare-dest", "--compress", "--compress-choice", "--compress-level",
  "--compress-threads", "--contimeout", "--copy-as", "--copy-dest", "--copy-devices", "--copy-dirlinks",
  "--copy-links", "--copy-unsafe-links", "--crtimes", "--cvs-exclude", "--debug", "--del", "--delay-updates",
  "--delete", "--delete-after", "--delete-before", "--delete-delay", "--delete-during", "--delete-excluded",
  "--delete-missing-args", "--devices", "--dirs", "--dry-run", "--early-input", "--exclude", "--exclude-from",
  "--executability", "--existing", "--fake-super", "--files-from", "--filter", "--force", "--from0", "--fsync",
  "--fuzzy", "--group", "--groupmap", "--hard-links", "--help", "--human-readable", "--iconv", "--ignore-errors",
  "--ignore-existing", "--ignore-missing-args", "--ignore-times", "--include", "--include-from", "--info",
  "--inplace", "--ipv4", "--ipv6", "--itemize-changes", "--keep-dirlinks", "--link-dest", "--links", "--list-only",
  "--log-file", "--log-file-format", "--max-alloc", "--max-delete", "--max-size", "--min-size", "--mkpath",
  "--modify-window", "--munge-links", "--no-implied-dirs", "--no-motd", "--numeric-ids", "--old-args",
  "--omit-dir-times", "--omit-link-times", "--one-file-system", "--only-write-batch", "--open-noatime",
  "--out-format", "--outbuf", "--owner", "--partial", "--partial-dir", "--password-file", "--perms", "--port",
  "--preallocate", "--progress", "--protocol", "--prune-empty-dirs", "--quiet", "--read-batch", "--recursive",
  "--relative", "--remote-option", "--remove-source-files", "--rsh", "--rsync-path", "--safe-links",
  "--secluded-args", "--size-only", "--skip-compress", "--sockopts", "--sparse", "--specials", "--stats", "--stderr",
  "--stop-after", "--stop-at", "--suffix", "--super", "--temp-dir", "--timeout", "--times", "--trust-sender",
  "--update", "--usermap", "--verbose", "--version", "--whole-file", "--write-batch", "--write-devices", "--xattrs"
], [
  "--address", "--backup-dir", "--block-size", "--bwlimit", "--checksum-choice", "--checksum-seed", "--chmod",
  "--chown", "--compare-dest", "--compress-choice", "--compress-level", "--compress-threads", "--contimeout",
  "--copy-as", "--copy-dest", "--debug", "--early-input", "--exclude", "--exclude-from", "--files-from", "--filter",
  "--groupmap", "--iconv", "--include", "--include-from", "--info", "--link-dest", "--log-file", "--log-file-format",
  "--max-alloc", "--max-delete", "--max-size", "--min-size", "--modify-window", "--only-write-batch", "--out-format",
  "--outbuf", "--partial-dir", "--password-file", "--port", "--protocol", "--read-batch", "--remote-option", "--rsh",
  "--rsync-path", "--skip-compress", "--sockopts", "--stderr", "--stop-after", "--stop-at", "--suffix", "--temp-dir",
  "--timeout", "--usermap", "--write-batch"
], "0468@ABCDEFHIJKLMNOPRSTUVWXabcdefghiklmnopqrstuvxyz", "@BMTef", { negatable: true, exact: true });

// git's global options, the words before the subcommand (cli/oversight-shell-writes.mjs gitInvocation). From git
// 2.54.0 `git help git` OPTIONS, and git 2.39.5's --super-prefix; measured on both: valued — the ones that take the
// next word as their value (`git --attr-source HEAD checkout`, `git --config-env k=VAR rm`); each of them also takes
// `--opt=value`, as do --exec-path and --list-cmds; valueless — the rest. git has no abbreviations here
// (`--no-pag` and `--git-di=` are unknown options) and no attached short value (`-Cdir`, `-ck=v` are unknown).
export const GIT_GLOBAL = Object.freeze({
  valued: ["-C", "-c", "--git-dir", "--work-tree", "--namespace", "--config-env", "--attr-source", "--super-prefix"],
  eqValued: ["--git-dir", "--work-tree", "--namespace", "--config-env", "--attr-source", "--super-prefix", "--exec-path", "--list-cmds"],
  valueless: ["-v", "--version", "-h", "--help", "-p", "--paginate", "-P", "--no-pager", "--exec-path", "--html-path", "--man-path", "--info-path",
    "--bare", "--no-replace-objects", "--no-lazy-fetch", "--no-optional-locks", "--no-advice", "--literal-pathspecs", "--glob-pathspecs",
    "--noglob-pathspecs", "--icase-pathspecs"]
});
// git's builtins: the words in `git --list-cmds=builtins` on each of git 2.39.5, 2.47.3 and 2.54.0, exactly as
// spelt. Only these name a command git runs itself. Any other word is an alias, a script or external git-<name> (git
// svn, subtree, send-email, lfs: measured, `git -c alias.svn='!cmd' svn` runs the alias where git-svn is not
// installed, on 2.39.5 and 2.54.0) or a builtin in another case (2.39.5 runs alias.checkout for `git CHECKOUT`;
// 2.54.0 on a case-insensitive disk runs git-core/git-CHECKOUT, which refuses).
export const GIT_BUILTINS = new Set([
  "add", "am", "annotate", "apply", "archive", "blame", "branch", "bugreport", "bundle", "cat-file", "check-attr",
  "check-ignore", "check-mailmap", "check-ref-format", "checkout", "checkout--worker", "checkout-index", "cherry",
  "cherry-pick", "clean", "clone", "column", "commit", "commit-graph", "commit-tree", "config", "count-objects",
  "credential", "credential-cache", "credential-cache--daemon", "credential-store", "describe", "diagnose", "diff",
  "diff-files", "diff-index", "diff-tree", "difftool", "fast-export", "fast-import", "fetch", "fetch-pack",
  "fmt-merge-msg", "for-each-ref", "for-each-repo", "format-patch", "fsck", "fsck-objects", "fsmonitor--daemon", "gc",
  "get-tar-commit-id", "grep", "hash-object", "help", "hook", "index-pack", "init", "init-db", "interpret-trailers",
  "log", "ls-files", "ls-remote", "ls-tree", "mailinfo", "mailsplit", "maintenance", "merge", "merge-base",
  "merge-file", "merge-index", "merge-ours", "merge-recursive", "merge-recursive-ours", "merge-recursive-theirs",
  "merge-subtree", "merge-tree", "mktag", "mktree", "multi-pack-index", "mv", "name-rev", "notes", "pack-objects",
  "pack-redundant", "pack-refs", "patch-id", "pickaxe", "prune", "prune-packed", "pull", "push", "range-diff",
  "read-tree", "rebase", "receive-pack", "reflog", "remote", "remote-ext", "remote-fd", "repack", "replace", "rerere",
  "reset", "restore", "rev-list", "rev-parse", "revert", "rm", "send-pack", "shortlog", "show", "show-branch",
  "show-index", "show-ref", "sparse-checkout", "stage", "stash", "status", "stripspace", "submodule--helper",
  "switch", "symbolic-ref", "tag", "unpack-file", "unpack-objects", "update-index", "update-ref",
  "update-server-info", "upload-archive", "upload-archive--writer", "upload-pack", "var", "verify-commit",
  "verify-pack", "verify-tag", "version", "whatchanged", "worktree", "write-tree"
]);
// Config keys a git command line may set (-c, --config-env, GIT_CONFIG_KEY_<n>) that run nothing and write nowhere:
// sections — every key under them; keys — single keys (lowercased, as git compares section and name). Any other key
// may run a command (core.fsmonitor, core.pager, pager.*, core.editor, diff.external, credential.helper,
// core.hooksPath, filter.*, alias.* … measured: -c core.fsmonitor=… runs on status, checkout and rm --cached, -c
// core.pager / pager.log on a terminal, git 2.39.5 and 2.54.0) or write a file (http.cookieFile), and is unknown.
export const GIT_SAFE_CONFIG = Object.freeze({
  sections: ["user", "author", "committer", "color", "advice", "log", "i18n", "column"],
  keys: ["core.quotepath", "core.autocrlf", "core.safecrlf", "core.eol", "core.filemode", "core.ignorecase", "core.precomposeunicode",
    "core.longpaths", "core.abbrev", "init.defaultbranch", "safe.directory", "protocol.version", "http.sslverify", "http.version",
    "http.postbuffer", "http.lowspeedlimit", "http.lowspeedtime", "commit.gpgsign", "tag.gpgsign", "gc.auto", "maintenance.auto",
    "pull.rebase", "pull.ff", "fetch.prune", "push.default", "push.autosetupremote", "merge.ff", "diff.renames", "diff.noprefix",
    "status.showuntrackedfiles"]
});
// Environment variables that make git run a program (measured, git 2.39.5 and 2.54.0: GIT_PAGER / PAGER for log and
// diff on a terminal, GIT_EDITOR / EDITOR for commit, GIT_SSH_COMMAND / GIT_SSH / GIT_PROXY_COMMAND for fetch,
// GIT_EXTERNAL_DIFF for diff; VISUAL, GIT_SEQUENCE_EDITOR, GIT_ASKPASS and SSH_ASKPASS where git asks for an editor
// on a terminal, a rebase todo or a password). Set on a git command with a value outside GIT_HARMLESS_PROGRAMS
// (GIT_HARMLESS_EDITORS too for the editor ones), the command is unknown.
export const GIT_EXEC_ENV = Object.freeze(["GIT_PAGER", "PAGER", "GIT_EDITOR", "EDITOR", "VISUAL", "GIT_SEQUENCE_EDITOR", "GIT_SSH_COMMAND", "GIT_SSH",
  "GIT_ASKPASS", "SSH_ASKPASS", "GIT_EXTERNAL_DIFF", "GIT_PROXY_COMMAND"]);
export const GIT_EDITOR_ENV = Object.freeze(["GIT_EDITOR", "EDITOR", "VISUAL", "GIT_SEQUENCE_EDITOR"]);
export const GIT_HARMLESS_PROGRAMS = Object.freeze(["", "cat", "less", "more", "true", ":"]);
export const GIT_HARMLESS_EDITORS = Object.freeze(["vi", "vim", "nano", "code --wait"]);
// Environment variables that make git run hooks, read config or write files somewhere the command does not show:
// GIT_COMMON_DIR (its hooks run: post-checkout, post-index-change), GIT_TEMPLATE_DIR (its hooks are copied in, and
// clone runs post-checkout at once), GIT_OBJECT_DIRECTORY (git add writes objects there), all measured on git 2.39.5
// and 2.54.0; GIT_CONFIG_GLOBAL / GIT_CONFIG_SYSTEM / HOME / XDG_CONFIG_HOME (a config whose core.fsmonitor runs),
// GIT_CONFIG_PARAMETERS and GIT_EXEC_PATH (cd65c42's measurements); GIT_REDIRECT_STDIN / STDOUT / STDERR (Git for
// Windows: a file in place of the stream; not measured here).
export const GIT_OPAQUE_ENV = Object.freeze(["GIT_COMMON_DIR", "GIT_TEMPLATE_DIR", "GIT_OBJECT_DIRECTORY", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM",
  "GIT_CONFIG_PARAMETERS", "GIT_EXEC_PATH", "HOME", "XDG_CONFIG_HOME", "GIT_REDIRECT_STDIN", "GIT_REDIRECT_STDOUT", "GIT_REDIRECT_STDERR"]);
// git clone / init / config: each one's options as `git clone -h`, `git init -h`, `git config --get -h` (the
// action-style command line) and `git config set -h` / `unset -h` / `rename-section -h` / `remove-section -h` /
// `edit -h` print them on git 2.54.0 (a superset of 2.39.5's, which has no config subcommands, --comment, --show-names
// or --append). git reads a unique prefix of a long option as that option and takes --no-<option> (measured, 2.39.5
// and 2.54.0: `git clone --templ=d`, `--conf core.hooksPath=h`, `git init --t d`, `git config --fil=f`, `--glob`);
// an unknown or ambiguous one is refused. Options the help lists only by their --no- name (clone --no-checkout,
// --no-hardlinks) are listed with their positive form too, as git accepts it. init-db is init.
export const GIT_CLONE = opts([
  "--also-filter-submodules", "--bare", "--branch", "--bundle-uri", "--checkout", "--config", "--depth", "--dissociate", "--filter",
  "--hardlinks", "--ipv4", "--ipv6", "--jobs", "--local", "--mirror", "--no-checkout", "--no-hardlinks", "--origin", "--progress", "--quiet",
  "--recurse-submodules", "--recursive", "--ref-format", "--reference", "--reference-if-able", "--reject-shallow", "--remote-submodules",
  "--revision", "--separate-git-dir", "--server-option", "--shallow-exclude", "--shallow-since", "--shallow-submodules", "--shared",
  "--single-branch", "--sparse", "--tags", "--template", "--upload-pack", "--verbose"
], ["--branch", "--bundle-uri", "--config", "--depth", "--filter", "--jobs", "--origin", "--ref-format", "--reference", "--reference-if-able",
  "--revision", "--separate-git-dir", "--server-option", "--shallow-exclude", "--shallow-since", "--template", "--upload-pack"], "46bcjlnoqsuv", "bcjou", { negatable: true });
export const GIT_INIT = opts([
  "--bare", "--initial-branch", "--object-format", "--quiet", "--ref-format", "--separate-git-dir", "--shared", "--template"
], ["--initial-branch", "--object-format", "--ref-format", "--separate-git-dir", "--template"], "bq", "b", { negatable: true });
// git config reads options only up to its first other word (measured, 2.39.5 and 2.54.0: `git config core.pager --get`
// sets core.pager to "--get"); a subcommand is read only as the first word (`git config --global set k v` is the key
// "set"). neg: the options that take --no-<option> (the help's "--[no-]"; an action does not).
const CONFIG_WHERE = ["--blob", "--file", "--global", "--local", "--system", "--worktree"];
const CONFIG_TYPE = ["--bool", "--bool-or-int", "--bool-or-str", "--expiry-date", "--int", "--path", "--type"];
const CONFIG_NEG = ["--all", "--append", "--blob", "--comment", "--default", "--file", "--fixed-value", "--global", "--includes", "--local", "--name-only",
  "--null", "--regexp", "--show-names", "--show-origin", "--show-scope", "--system", "--type", "--url", "--value", "--worktree"];
const configOpts = (more, valued, short, shortValued) => opts([...CONFIG_WHERE, ...more].sort(), ["--blob", "--file", ...valued], short, shortValued, { neg: CONFIG_NEG });
export const GIT_CONFIG = Object.freeze({
  legacy: configOpts([...CONFIG_TYPE, "--add", "--comment", "--default", "--edit", "--fixed-value", "--get", "--get-all", "--get-color", "--get-colorbool",
    "--get-regexp", "--get-urlmatch", "--includes", "--list", "--name-only", "--null", "--remove-section", "--rename-section", "--replace-all",
    "--show-names", "--show-origin", "--show-scope", "--unset", "--unset-all"], ["--comment", "--default", "--type"], "eflzt", "ft"),
  set: configOpts([...CONFIG_TYPE, "--all", "--append", "--comment", "--fixed-value", "--value"], ["--comment", "--type", "--value"], "ft", "ft"),
  unset: configOpts(["--all", "--fixed-value", "--value"], ["--value"], "f", "f"),
  "rename-section": configOpts([], [], "f", "f"),
  "remove-section": configOpts([], [], "f", "f"),
  edit: configOpts([], [], "f", "f"),
  short: { e: "--edit", f: "--file", l: "--list", t: "--type", z: "--null" }
});
// The options that name the program run for the other end of a transfer (`git <cmd> -h` on 2.54.0: fetch, pull and
// ls-remote "--[no-]upload-pack <path>", push and send-pack "--[no-]receive-pack" and "--[no-]exec", archive
// "--[no-]exec <command>"; fetch-pack's usage "--upload-pack=<git-upload-pack>", and it reads --exec= too). A command
// value runs, measured on 2.39.5 and 2.54.0 with a local repository, as does clone -u / --upload-pack (GIT_CLONE).
// None has a short letter (`git ls-remote -u` is refused). A long option written as any prefix of one is read as it.
export const GIT_PACK_PROGRAM = Object.freeze({
  fetch: ["--upload-pack"], pull: ["--upload-pack"], "ls-remote": ["--upload-pack"], "fetch-pack": ["--upload-pack", "--exec"],
  push: ["--receive-pack", "--exec"], "send-pack": ["--receive-pack", "--exec"], archive: ["--exec"]
});
