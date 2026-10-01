# A container that runs Claude Code headless (`claude -p`, or an Agent SDK service) with MoorAI in server mode.
#
#   docker build -t agent-with-moorai examples/server
#   docker run --rm \
#     -e ANTHROPIC_API_KEY \
#     -e MOORAI_SERVER_URL -e MOORAI_TENANT -e MOORAI_INSTALL_TOKEN -e MOORAI_SERVICE_ID=billing-agent \
#     -v "$PWD:/work" agent-with-moorai -p "Summarise the open TODOs in this repository"
#
# Secrets (the API key, the install token) are passed at run time and never baked into the image.
FROM node:22-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/*

RUN npm install -g @anthropic-ai/claude-code

# Pin MOORAI_REF to a release tag in production.
ARG MOORAI_REF=main
RUN git clone --depth 1 --branch "$MOORAI_REF" https://github.com/gitayg/moorai.git /opt/moorai

# Register MoorAI's hooks in Claude Code's MANAGED settings (Linux: /etc/claude-code/managed-settings.json).
# A repository the agent works on cannot switch managed hooks off; a user-level registration it could.
RUN node /opt/moorai/examples/server/managed-settings.mjs /etc/claude-code/managed-settings.json

# Server mode: ask becomes deny (no approver), identity is the workload name, enforcement without a laptop.
# Set the console binding (MOORAI_SERVER_URL, MOORAI_TENANT, MOORAI_INSTALL_TOKEN) and MOORAI_SERVICE_ID
# in the job or pod environment, or in a root-owned /etc/moorai/config.json, never in a settings file.
ENV MOORAI_MODE=server

RUN useradd --create-home agent
USER agent
WORKDIR /work
ENTRYPOINT ["claude"]
