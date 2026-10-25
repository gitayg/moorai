#!/bin/sh
# Install the MoorAI .deb on a clean Debian or Ubuntu and run the installed hook. Run it as root inside a
# throwaway container with the built packages mounted at /pkg (release-linux.yml runs it in ubuntu:20.04):
#
#   docker run --rm --platform linux/amd64 -v "$PWD/dist/linux:/pkg:ro" -v "$PWD/packaging/linux/smoke-test.sh:/smoke-test.sh:ro" \
#     ubuntu:20.04 sh /smoke-test.sh
#
# 1. dpkg -i with no Node: the package installs and warns.  2. Node (NODE_VERSION, official tarball, checked
# against SHASUMS256.txt) into /usr/local.  3. moorai-install-hooks as root.  4. The installed hook on a
# source-file Read: exit 0, no output (allowed).  5. The same hook on a credential-file Read under the
# root-owned fail-closed posture: exit 0 with a deny, so step 4 proves a hook that ran, not one that did nothing.
set -eu
NODE_VERSION=${NODE_VERSION:-22.22.0}
export DEBIAN_FRONTEND=noninteractive

deb=$(ls /pkg/moorai_*_all.deb)
echo "== glibc: $(ldd --version | head -n 1)"

echo "== dpkg -i without Node"
apt-get update -qq
apt-get install -y -qq --no-install-recommends ca-certificates curl xz-utils >/dev/null
dpkg -i "$deb" >/tmp/dpkg.log 2>&1 || { cat /tmp/dpkg.log; echo "FAIL: dpkg -i"; exit 1; }
cat /tmp/dpkg.log
grep -q "need Node.js 18 or newer" /tmp/dpkg.log || { echo "FAIL: no missing-Node warning"; exit 1; }

echo "== Node v$NODE_VERSION"
case "$(dpkg --print-architecture)" in
  amd64) arch=x64 ;;
  arm64) arch=arm64 ;;
  *) echo "FAIL: unsupported architecture $(dpkg --print-architecture)"; exit 1 ;;
esac
tgz="node-v$NODE_VERSION-linux-$arch.tar.xz"
cd /tmp
curl -fsSLO "https://nodejs.org/dist/v$NODE_VERSION/$tgz"
curl -fsSLO "https://nodejs.org/dist/v$NODE_VERSION/SHASUMS256.txt"
grep " $tgz\$" SHASUMS256.txt | sha256sum -c -
tar -xJf "$tgz" -C /usr/local --strip-components=1
node --version
sh /usr/lib/moorai/linux/moorai-node --check

echo "== moorai-install-hooks"
mkdir -p /tmp/proj
cd /tmp/proj
moorai-install-hooks
grep -q moorai-hook "$HOME/.claude/settings.json" || { echo "FAIL: hook not registered"; exit 1; }

echo "== hook: source-file Read"
printf 'export const add = (a, b) => a + b;\n' > /tmp/proj/math.js
out=$(printf '%s' '{"hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"file_path":"/tmp/proj/math.js"},"session_id":"linux-smoke","cwd":"/tmp/proj"}' | moorai-hook)
echo "exit 0, output: '${out}'"
[ -z "$out" ] || { echo "FAIL: a source-file Read was not allowed silently"; exit 1; }

echo "== hook: credential-file Read under the fail-closed posture"
printf 'fail-closed\n' > /etc/moorai/offline-posture
printf 'AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIK7MDENGbPxRfiCYzEXAMPLEKEY1\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n' > /tmp/proj/.env
out=$(printf '%s' '{"hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"file_path":"/tmp/proj/.env"},"session_id":"linux-smoke","cwd":"/tmp/proj"}' | moorai-hook)
decision=$(printf '%s' "$out" | node -e 'let s="";process.stdin.on("data",(d)=>s+=d).on("end",()=>{try{process.stdout.write(JSON.parse(s).hookSpecificOutput.permissionDecision||"")}catch{}})')
echo "exit 0, decision: ${decision}"
[ "$decision" = "deny" ] || { echo "FAIL: expected deny, got: $out"; exit 1; }
rm -f /etc/moorai/offline-posture

echo "== smoke test passed"
