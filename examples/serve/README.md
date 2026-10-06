# MoorAI as a sidecar

`ghcr.io/gitayg/moorai-server` runs the MoorAI engine next to an agent that is not Claude Code: one image,
two commands.

| Command | What it does | Port (loopback) |
|---|---|---|
| `moorai-serve` (default) | HTTP decision API: `POST /v1/tool-call`, `POST /v1/scan`, `GET /healthz` | 8790 |
| `moorai-mcp-gateway --route /name=https://...` | Guard in front of remote MCP servers | 8848 |

Both listen on 127.0.0.1 only and refuse a request whose Host header is not a loopback name. Run the
sidecar in the agent's network namespace: a container in the same Kubernetes pod, or a compose service
with `network_mode: "service:<agent>"`. Nothing is published and no other pod can reach it.

The image is `node:22-slim` plus the files the npm package ships, runs as uid 1000 (`node`), and has no
npm dependencies installed. Pin a release tag (`:1.2.0`) in production; `:latest` follows the newest tag.

## Files

- `docker-compose.yml` runs the sidecar with a demo agent (`demo-agent.mjs`). The demo sends a reverse
  shell, a benign command, a prompt injection and a request with a foreign Host header, then prints the
  verdicts and the alerts the sidecar posted to a stand-in console.

      docker compose -f examples/serve/docker-compose.yml up --build --abort-on-container-exit --exit-code-from agent
      docker compose -f examples/serve/docker-compose.yml down

- `k8s-sidecar.yaml` has two Deployments: an agent with `moorai-serve`, and an MCP client with
  `moorai-mcp-gateway`. Create the install-token Secret first:

      kubectl create secret generic moorai-install --from-literal=token=<install token from the console>
      kubectl apply -f examples/serve/k8s-sidecar.yaml

## Configuration (environment)

| Variable | Meaning |
|---|---|
| `MOORAI_SERVICE_ID` | Workload name. Alerts and policy matching use it instead of a pod hostname. |
| `MOORAI_SERVER_URL`, `MOORAI_TENANT`, `MOORAI_INSTALL_TOKEN` | Console binding. Put the token in a Secret. Without a console the sidecar still decides, and reports nothing. |
| `MOORAI_K8S_POD`, `MOORAI_K8S_NAMESPACE`, `MOORAI_K8S_NODE` | Set from the downward API (`metadata.name`, `metadata.namespace`, `spec.nodeName`). |
| `MOORAI_HEALTH_PORT`, `MOORAI_HEALTH_PATH` | Health check target. Defaults to `8790` and `/healthz`; set `8848` and `/` for the gateway. |

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
