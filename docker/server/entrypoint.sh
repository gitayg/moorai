#!/bin/sh
# moorai-server image entrypoint. No arguments, or arguments that start with "-", run moorai-serve
# (`docker run img --port 9000` == `docker run img moorai-serve --port 9000`); anything else is run as
# given, so `docker run img moorai-mcp-gateway --route /github=https://...` selects the gateway and
# `docker run img moorai-model-proxy` the model proxy.
set -e
case "${1:-}" in
  ""|-*) set -- moorai-serve "$@" ;;
esac
exec "$@"
