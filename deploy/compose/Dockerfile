# The MoorAI server image with this deployment's machine-wide config baked in at /etc/moorai/config.json,
# root:root 0644 in a root:root 0755 directory: root-owned and not group- or world-writable, which is what
# readRootOwned requires of a trust source, and readable by the image's user 1000. A bind mount of a host
# file would carry the host user's uid and be ignored. (COPY --chmod alone leaves the directory it creates
# unreadable to user 1000: measured, the config then reads as absent.)
ARG MOORAI_IMAGE=ghcr.io/gitayg/moorai-server:latest
FROM ${MOORAI_IMAGE}
USER 0:0
RUN install -d -o 0 -g 0 -m 0755 /etc/moorai
COPY --chown=0:0 --chmod=0644 moorai-system.json /etc/moorai/config.json
USER 1000:1000
