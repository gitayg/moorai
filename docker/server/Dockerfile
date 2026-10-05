# syntax=docker/dockerfile:1
# ghcr.io/gitayg/moorai-server — the MoorAI engine as a sidecar: moorai-serve (the localhost HTTP
# decision API, default) or moorai-mcp-gateway (the HTTP MCP guard), one image, two commands.
#
#   docker build -f docker/server/Dockerfile -t moorai-server .
#   docker run --rm moorai-server                                   # moorai-serve on 127.0.0.1:8790
#   docker run --rm moorai-server moorai-mcp-gateway --route /github=https://api.githubcopilot.com/mcp/
#
# Both bind loopback, so they are meant to share the agent's network namespace (a Kubernetes pod, or
# compose `network_mode: "service:<agent>"`): examples/serve/. Console binding and workload name come from
# the environment at run time (MOORAI_SERVER_URL, MOORAI_TENANT, MOORAI_INSTALL_TOKEN, MOORAI_SERVICE_ID;
# MOORAI_K8S_POD / _NAMESPACE / _NODE from the downward API) — never baked into the image.
#
# Contents: exactly the package.json "files" set (what `npm pack` ships) plus package.json and LICENSE.
# Neither entrypoint imports an npm package (test/server-image.test.mjs walks both import closures and
# fails on a bare specifier or on a file no COPY line covers), so there is no `npm install` at all.
FROM node:22-slim

LABEL org.opencontainers.image.title="MoorAI server" \
      org.opencontainers.image.description="MoorAI engine as a sidecar: moorai-serve (localhost HTTP decision API for agent loops) and moorai-mcp-gateway (guard for remote MCP servers). MIT." \
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
COPY mcp-proxy/tool-scan.mjs mcp-proxy/tool-baseline.mjs mcp-proxy/
COPY cloud/ cloud/
COPY packages/agent-sdk/src/ packages/agent-sdk/src/
COPY --chmod=755 docker/server/entrypoint.sh /usr/local/bin/moorai-entrypoint
COPY docker/server/healthcheck.mjs /opt/moorai/docker/healthcheck.mjs

RUN printf '#!/bin/sh\nexec node /opt/moorai/cli/moorai-serve.mjs "$@"\n' > /usr/local/bin/moorai-serve \
 && printf '#!/bin/sh\nexec node /opt/moorai/mcp-gateway/moorai-mcp-gateway.mjs "$@"\n' > /usr/local/bin/moorai-mcp-gateway \
 && chmod 755 /usr/local/bin/moorai-serve /usr/local/bin/moorai-mcp-gateway

# Server mode: the workload name (MOORAI_SERVICE_ID) is the identity instead of a per-deploy hostname,
# and a "justify" verdict with no approver is a deny. moorai-serve forces this anyway; the gateway reads it.
ENV NODE_ENV=production \
    MOORAI_MODE=server

# The image's own non-root user (uid 1000). Its home holds the policy cache / pin; give it a writable
# emptyDir when the root filesystem is read-only.
USER node
EXPOSE 8790

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["node", "/opt/moorai/docker/healthcheck.mjs"]

ENTRYPOINT ["moorai-entrypoint"]
CMD ["moorai-serve"]
