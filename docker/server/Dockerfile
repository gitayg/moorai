# syntax=docker/dockerfile:1
# ghcr.io/gitayg/moorai-server — the MoorAI engine as a sidecar: moorai-serve (the localhost HTTP
# decision API, default), moorai-mcp-gateway (the HTTP MCP guard) or moorai-model-proxy (between an agent's
# model SDK and the provider), one image, three commands.
#
#   docker build -f docker/server/Dockerfile -t moorai-server .
#   docker run --rm moorai-server                                   # moorai-serve on 127.0.0.1:8790
#   docker run --rm moorai-server moorai-mcp-gateway --route /github=https://api.githubcopilot.com/mcp/
#   docker run --rm -e MOORAI_HEALTH_PORT=8791 moorai-server moorai-model-proxy   # report-only, 127.0.0.1:8791
#
# All three bind loopback, so they are meant to share the agent's network namespace (a Kubernetes pod, or
# compose `network_mode: "service:<agent>"`): examples/serve/. Console binding and workload name come from
# the environment at run time (MOORAI_SERVER_URL, MOORAI_TENANT, MOORAI_INSTALL_TOKEN, MOORAI_SERVICE_ID;
# MOORAI_K8S_POD / _NAMESPACE / _NODE from the downward API) — never baked into the image.
#
# Contents: exactly the package.json "files" set (what `npm pack` ships) plus package.json and LICENSE.
# No entrypoint imports an npm package (test/server-image.test.mjs walks every import closure and
# fails on a bare specifier or on a file no COPY line covers), so there is no `npm install` at all.
FROM node:22-slim

LABEL org.opencontainers.image.title="MoorAI server" \
      org.opencontainers.image.description="MoorAI engine as a sidecar: moorai-serve (localhost HTTP decision API for agent loops), moorai-mcp-gateway (guard for remote MCP servers) and moorai-model-proxy (guard between an agent and its model provider). MIT." \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/gitayg/moorai"

WORKDIR /opt/moorai
COPY package.json LICENSE scan.mjs ./
COPY cli/ cli/
COPY src/ src/
COPY data/ data/
COPY scripts/redteam.mjs scripts/accepted-failures.mjs scripts/
COPY test/redteam/corpus.json test/redteam/
COPY mcp-gateway/ mcp-gateway/
COPY model-proxy/ model-proxy/
COPY mcp-proxy/tool-scan.mjs mcp-proxy/tool-baseline.mjs mcp-proxy/tool-drift.mjs mcp-proxy/
COPY cloud/ cloud/
COPY packages/agent-sdk/src/ packages/agent-sdk/src/
COPY --chmod=755 docker/server/entrypoint.sh /usr/local/bin/moorai-entrypoint
COPY docker/server/healthcheck.mjs /opt/moorai/docker/healthcheck.mjs

RUN printf '#!/bin/sh\nexec node /opt/moorai/cli/moorai-serve.mjs "$@"\n' > /usr/local/bin/moorai-serve \
 && printf '#!/bin/sh\nexec node /opt/moorai/mcp-gateway/moorai-mcp-gateway.mjs "$@"\n' > /usr/local/bin/moorai-mcp-gateway \
 && printf '#!/bin/sh\nexec node /opt/moorai/model-proxy/moorai-model-proxy.mjs "$@"\n' > /usr/local/bin/moorai-model-proxy \
 && chmod 755 /usr/local/bin/moorai-serve /usr/local/bin/moorai-mcp-gateway /usr/local/bin/moorai-model-proxy

# Server mode: the workload name (MOORAI_SERVICE_ID) is the identity instead of a per-deploy hostname,
# and a "justify" verdict with no approver is a deny. moorai-serve forces this anyway; the gateway reads it.
ENV NODE_ENV=production \
    MOORAI_MODE=server

# The image's own non-root user `node`, by number (uid/gid 1000) so Kubernetes can verify
# `runAsNonRoot: true` without a `runAsUser`. Its home holds the policy cache / pin; give it a writable
# emptyDir when the root filesystem is read-only.
USER 1000:1000
EXPOSE 8790

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["node", "/opt/moorai/docker/healthcheck.mjs"]

ENTRYPOINT ["moorai-entrypoint"]
CMD ["moorai-serve"]
