// Container CLI host escape (MITRE ATT&CK T1059.013) through an AI coding agent: a container configured to
// break out onto the host. data/detectors.js CONTAINER_ESCAPE, part of action-security-config (#46).
//
// THE GAP. Nothing flagged a privileged container, a host-root bind mount, --pid=host, nsenter into init
// or a privileged kubectl pod (ATT&CK v20 gap analysis, probe: docker "-- none --").
//
//   node --test --import ./test/hermetic-env.mjs test/container-escape.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { DETECTOR_MODULE, scan, credit, assertLinear, runHook, withHome } from "./detector-gap-kit.mjs";
import { CONTAINER_ESCAPE } from "../data/detectors.js";

const { DETECTORS } = DETECTOR_MODULE;
const DET = "action-security-config#46";

const POSITIVES = [
  "docker run --privileged -it ubuntu bash",
  "docker run --rm --privileged --pid=host ubuntu nsenter -t 1 -m -u -i -n sh",
  "podman run --privileged alpine",
  "docker run -v /:/host -it alpine chroot /host",
  "docker run --volume /:/mnt ubuntu",
  "docker run --mount type=bind,source=/,target=/host ubuntu",
  "docker run --cap-add=SYS_ADMIN --security-opt apparmor=unconfined ubuntu",
  "docker run --cap-add ALL ubuntu",
  "docker run --pid host ubuntu",
  "nsenter -t 1 -m -u -i -n -p bash",
  "nsenter --target 1 --mount --uts --ipc --net --pid",
  "kubectl run pwn --image=ubuntu --privileged --overrides='{\"spec\":{\"hostPID\":true}}'",
  "kubectl apply -f - <<EOF\\nspec:\\n  hostPID: true\\nEOF"
];

const NEGATIVES = [
  "docker run -p 8080:80 nginx",
  "docker run -v $(pwd):/app node npm test",
  "docker run -v /home/dev/app:/app ubuntu",
  "docker run --rm -it ubuntu bash",
  "docker build -t myimage .",
  "docker ps -a",
  "podman images",
  "kubectl get pods -n prod",
  "kubectl run web --image=nginx --port=80",
  "nsenter --help",
  "docker run --network=host nginx",
  "docker run -v /var/run/docker.sock:/var/run/docker.sock docker"
];

for (const cmd of POSITIVES) {
  test(`T1059.013 positive: ${DET} fires on ${JSON.stringify(cmd)}`, () => {
    assert.ok(scan(cmd).includes(DET), `missed; findings: [${scan(cmd).join(",")}]`);
  });
}
for (const cmd of NEGATIVES) {
  test(`T1059.013 negative: ${DET} stays silent on ${JSON.stringify(cmd)}`, () => {
    assert.ok(!scan(cmd).includes(DET), `false positive; findings: [${scan(cmd).join(",")}]`);
  });
}

test("wiring: action-security-config holds the CONTAINER_ESCAPE pattern objects by reference", () => {
  const d = DETECTORS.find((x) => x.detectorId === "action-security-config");
  for (const rx of CONTAINER_ESCAPE) assert.ok(d.patterns.includes(rx), `missing ${rx}`);
});

test("ATT&CK: #46 credits T1059.013 as partial", () => {
  assert.equal(credit(46, "T1059.013")?.coverage, "partial");
});

test("pattern cost: 60KB adversarial inputs scan in linear time, pattern by pattern", () => {
  assertLinear(CONTAINER_ESCAPE, [
    ["", "docker run --privileged ", 2500],
    ["", "docker run --pid=host ", 2700],
    ["", "docker run --cap-add=ALL ", 2400],
    ["", "-v /:/host ", 6000],
    ["", "--mount source=/, ", 3300],
    ["", "nsenter --target 1 ", 3100],
    ["", "kubectl run --privileged ", 2300]
  ]);
});

test("hook e2e: a host-escape container asks (no policy: #46 is justify); an ordinary container is allowed", () => {
  withHome((home) => {
    assert.equal(runHook(home, "Bash", { command: "docker run --privileged -v /:/host alpine chroot /host" }), "ask");
    assert.equal(runHook(home, "Bash", { command: "nsenter -t 1 -m -u -i -n bash" }), "ask");
    assert.equal(runHook(home, "Bash", { command: "docker run -p 8080:80 nginx" }), "allow");
    assert.equal(runHook(home, "Bash", { command: "docker run -v $(pwd):/app node npm test" }), "allow");
  });
});
