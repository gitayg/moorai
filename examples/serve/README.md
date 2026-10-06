# MoorAI as a sidecar

`ghcr.io/gitayg/moorai-server` runs the MoorAI engine next to an agent that is not Claude Code: one image,
three commands.

| Command | What it does | Port (loopback) |
|---|---|---|
| `moorai-serve` (default) | HTTP decision API: `POST /v1/tool-call`, `POST /v1/scan`, `GET /healthz` | 8790 |
| `moorai-mcp-gateway --route /name=https://...` | Guard in front of remote MCP servers | 8848 |
| `moorai-model-proxy` | Between the agent's model SDK and the provider (Anthropic Messages, OpenAI Chat Completions); see [model-proxy/README.md](../../model-proxy/README.md) | 8791 |

All three listen on 127.0.0.1 only and refuse a request whose Host header is not a loopback name. Run the
sidecar in the agent's network namespace: a container in the same Kubernetes pod, or a compose service
with `network_mode: "service:<agent>"`. Nothing is published and no other pod can reach it.

The image is `node:22-slim` plus the files the npm package ships, runs as uid 1000 (`node`), and has no
npm dependencies installed. Pin a release tag (`:1.2.0`) in production; `:latest` follows the newest tag.

## Files

- `docker-compose.yml` runs two sidecars, `moorai-serve` and `moorai-model-proxy`, in one demo agent's
  network namespace. The agent runs two demos in turn, and each one plays the console on 127.0.0.1:8787 and
  prints the alerts its sidecar posted.
  - `demo-agent.mjs` sends a reverse shell, a benign command, a prompt injection and a request with a
    foreign Host header to `moorai-serve`, then prints the verdicts.
  - `demo-model-proxy.mjs` plays a fake Anthropic provider on 127.0.0.1:9100 (canned answers, no real
    model, a fake key) and makes three model calls through the proxy, which runs in report mode with its
    `--route` pointed at the fake provider:
    1. a plain question;
    2. a streamed turn where the model asks for a `bash` call that reads `~/.aws/credentials`;
    3. a turn that feeds back a tool result carrying a prompt injection.

    All three answers reach the agent byte-identical to what the provider sent, and the provider receives
    the client's own key. The tool call and the tool result are alerted, content-free. Nothing is
    executed.

      docker compose -f examples/serve/docker-compose.yml up --build --abort-on-container-exit --exit-code-from agent
      docker compose -f examples/serve/docker-compose.yml down

- `k8s-sidecar.yaml` has three Deployments:
  - `billing-agent`: an agent with `moorai-serve`;
  - `triage-agent`: an MCP client with `moorai-mcp-gateway`;
  - `research-agent`: an agent whose `ANTHROPIC_BASE_URL` / `OPENAI_BASE_URL` point at
    `moorai-model-proxy` on `127.0.0.1:8791`.

  The proxy runs in report mode with the real provider URLs as its routes. Add `--mode enforce` to refuse
  instead. The provider key stays in the agent container: the proxy forwards it upstream untouched, and
  the moorai container is given no key. Create the Secrets first:

      kubectl create secret generic moorai-install --from-literal=token=<install token from the console>
      kubectl create secret generic research-agent-provider --from-literal=anthropic-api-key=<your provider key>
      kubectl apply -f examples/serve/k8s-sidecar.yaml

## Configuration (environment)

| Variable | Meaning |
|---|---|
| `MOORAI_SERVICE_ID` | Workload name. Alerts and policy matching use it instead of a pod hostname. |
| `MOORAI_SERVER_URL`, `MOORAI_TENANT`, `MOORAI_INSTALL_TOKEN` | Console binding. Put the token in a Secret. Without a console the sidecar still decides, and reports nothing. |
| `MOORAI_K8S_POD`, `MOORAI_K8S_NAMESPACE`, `MOORAI_K8S_NODE` | Set from the downward API (`metadata.name`, `metadata.namespace`, `spec.nodeName`). |
| `MOORAI_HEALTH_PORT`, `MOORAI_HEALTH_PATH` | Health check target. Defaults to `8790` and `/healthz`; set `8848` and `/` for the gateway, and `8791` for the model proxy. |

The image sets `MOORAI_MODE=server`: a verdict that would ask a person is a deny, because there is no one
to ask.

## Probes

Use exec probes, not `httpGet`. The kubelet sends an HTTP probe to the pod IP, where nothing listens,
and the sidecar answers 421 to a non-loopback Host header. The exec probe
`node /opt/moorai/docker/healthcheck.mjs` runs inside the container and checks loopback. The image's
Docker `HEALTHCHECK` runs the same script.

## Workload identity on alerts

Every alert the sidecar or gateway posts to the console carries a `workload` object:

    "workload": { "containerId": "<64 hex>", "pod": "billing-agent-7d9f", "namespace": "prod", "node": "node-a" }

- `containerId` comes from `/proc/self/cgroup` (Docker, containerd, CRI-O and podman cgroup names). On
  cgroup v2 with a private cgroup namespace that file reads `0::/`, so the fallback is
  `/proc/self/mountinfo`, where Docker bind-mounts `/etc/hostname` from a path containing the id. Those
  files belong to the network namespace, so with compose `network_mode: "service:agent"` the id is the
  agent container's, the container the verdict is about. Under Kubernetes with containerd the container
  sees only its pod's sandbox id and pod UID, never its own container id, so `containerId` is absent
  (measured on kind v0.33.0, Kubernetes v1.37.0, containerd 2.3.4, cgroup v2; the sandbox id is not reported as a container id); `namespace` + `pod`
  are the join key there.
- `pod`, `namespace` and `node` come from the `MOORAI_K8S_*` variables.
- There is no `pid`: the sidecar is not the agent process.

A field that cannot be detected, or fails its format check, is left out. These are infrastructure
identifiers, so a SIEM can join MoorAI verdicts with host-sensor events on the same container or pod.

## Read-only root filesystem

The examples run with a read-only root filesystem. The policy cache lives in the user's home, so give
`/home/node` and `/tmp` a writable `emptyDir` (Kubernetes) or `tmpfs` (compose), as both examples do.

## How the examples are checked

Each check below uses the image built from this tree (version 1.4.0), last run on 2026-10-06.

**Docker Compose 5.2.0 (Docker 29.6.1).** `docker compose config` passes. `docker compose up` exits 0:

- `demo-agent.mjs`: the reverse shell is denied (#54), the benign command is allowed, and the foreign Host
  gets 421.
- `demo-model-proxy.mjs`: all three calls answer 200 byte-identical to the fake provider, with `"ok": true`.
  The console receives two alerts with surface `model-proxy`:
  - `model-proxy:Bash`, #55 Identity & Access;
  - `model-proxy:tool_result`, #40 Prompt Injection.

  Each alert carries the agent's `workload.containerId`.

**kind v0.33.0 (Kubernetes v1.37.0).**

1. `kubectl apply --dry-run=server --validate=strict -f examples/serve/k8s-sidecar.yaml`, on the file as
   shipped, creates all three Deployments. The same command rejects a misspelled field.
2. The image is built with `docker build -f docker/server/Dockerfile -t moorai-server:local .` and loaded
   with `kind load docker-image`.
3. A kustomize overlay, kept outside the repo, applies the unchanged manifest with these changes:
   - the image is swapped for `moorai-server:local` with `imagePullPolicy: Never`;
   - the placeholder agent images become the same image running the demo scripts from a ConfigMap
     (`DEMO_KEEP_ALIVE=1`), or an idle `node` for the MCP client;
   - `MOORAI_SERVER_URL` is the demo console on 127.0.0.1:8787;
   - the model proxy's `--route` is the demo's fake provider;
   - `moorai-install` holds a throwaway token.

The results:

- All three pods are 2/2 Ready, with 0 restarts, through the exec probes.
- In the model-proxy container, the healthcheck exits 0 with `MOORAI_HEALTH_PORT=8791` and 1 with 8790.
  The container runs as uid 1000, cannot write to `/opt`, and can write to the `/home/node` emptyDir.
- The `research-agent` demo prints the same three byte-identical 200s and the same two alerts, each with
  `"workload": {"pod": "research-agent-…", "namespace": "default", "node": "moorai-mp-control-plane"}`.
- The `billing-agent` demo prints the same verdicts as under compose, and its alerts carry the pod,
  namespace and node.

Not covered by these runs:

- enforce mode in a cluster (the model-proxy tests cover it);
- a real provider or SDK;
- the triage gateway forwarding to its upstream.
