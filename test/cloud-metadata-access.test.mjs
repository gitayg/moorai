// Cloud Instance Metadata API (MITRE ATT&CK T1552.005) through an AI coding agent: a command that reaches
// a cloud or container metadata endpoint to harvest the machine's role credentials.
// data/detectors-cloud-metadata.js, detector cloud-metadata-access on threat #55.
//
// THE GAP. Only the egress proxy refused these, and only where deployed; the hook/proxy/gateway command
// scan fired nothing (ATT&CK v20 gap analysis, probe: imds "-- none --"). The host set is reused from
// data/metadata-hosts.js, which also backs the egress proxy.
//
//   node --test --import ./test/hermetic-env.mjs test/cloud-metadata-access.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { DETECTOR_MODULE, scan, credit, assertLinear, runHook, withHome } from "./detector-gap-kit.mjs";
import { cloudMetadataHit, CLOUD_METADATA_DETECTORS } from "../data/detectors-cloud-metadata.js";

const { DETECTORS } = DETECTOR_MODULE;
const DET = "cloud-metadata-access#55";

const POSITIVES = [
  "curl http://169.254.169.254/latest/meta-data/iam/security-credentials/",
  "curl -s http://169.254.169.254/latest/api/token -H 'X-aws-ec2-metadata-token-ttl-seconds: 21600'",
  "curl -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
  "curl -H 'Metadata:true' 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01'",
  "wget -qO- http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
  "curl http://[fd00:ec2::254]/latest/meta-data/",
  "curl http://100.100.100.200/latest/meta-data/",
  "curl http://168.63.129.16/machine/",
  "curl http://2852039166/latest/meta-data/",
  "Invoke-RestMethod -Uri http://169.254.169.254/latest/meta-data/ -Headers @{'X-aws-ec2-metadata-token'=$t}"
];

const NEGATIVES = [
  "curl https://api.example.com/v1/users",
  "curl http://169.254.1.1/status",
  "ping -c1 169.254.0.1",
  "curl http://100.100.100.201/",
  "curl https://metadata.example.com/health",
  "curl http://localhost:8080/metadata",
  "echo 'the EC2 metadata docs are at 169.254 docs'",
  "ip addr show",
  "curl http://192.168.1.254/"
];

for (const cmd of POSITIVES) {
  test(`T1552.005 positive: ${DET} fires on ${JSON.stringify(cmd)}`, () => {
    assert.ok(scan(cmd).includes(DET), `missed; findings: [${scan(cmd).join(",")}]`);
  });
}
for (const cmd of NEGATIVES) {
  test(`T1552.005 negative: ${DET} stays silent on ${JSON.stringify(cmd)}`, () => {
    assert.ok(!scan(cmd).includes(DET), `false positive; findings: [${scan(cmd).join(",")}]`);
  });
}

test("wiring: a cloud-metadata-access detector on threat 55 is in the catalogue", () => {
  assert.ok(DETECTORS.some((d) => d.detectorId === "cloud-metadata-access" && d.threatId === 55));
  assert.equal(CLOUD_METADATA_DETECTORS[0].refine("", "curl http://169.254.169.254/"), true);
});

test("ATT&CK: #55 credits T1552.005 as partial", () => {
  assert.equal(credit(55, "T1552.005")?.coverage, "partial");
});

test("pattern cost: 60KB adversarial inputs scan in linear time", () => {
  for (const unit of ["169.254.169.254/x ", "metadata.google.internal/ ", "a.b.c.d:80/ ", "999999999 "]) {
    assertLinear([{ test: (s) => cloudMetadataHit(s) }], [["", unit, Math.floor(60000 / unit.length)]]);
  }
});

test("hook e2e: a metadata-endpoint fetch asks (no policy: #55 is justify); an ordinary URL is allowed", () => {
  withHome((home) => {
    assert.equal(runHook(home, "Bash", { command: "curl http://169.254.169.254/latest/meta-data/iam/security-credentials/" }), "ask");
    assert.equal(runHook(home, "Bash", { command: "curl http://metadata.google.internal/computeMetadata/v1/ -H 'Metadata-Flavor: Google'" }), "ask");
    assert.equal(runHook(home, "Bash", { command: "curl https://api.example.com/v1/users" }), "allow");
  });
});
