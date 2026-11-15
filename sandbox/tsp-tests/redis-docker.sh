#!/usr/bin/env bash
# The pinned Redis image standing in for a local `redis-server` binary, for the `mediator` job (Railroad 11681:
# "Redis 7.4.6-alpine by digest"). Every argument goes to redis-server unchanged; the scripts that call it
# (mediator-line-d.sh, mediator-acl.mjs) pass --port/--bind 127.0.0.1/--requirepass <a random test marker>.
# Host networking so 127.0.0.1 is the runner's. SIGTERM to this process reaches redis (docker's sig-proxy) and --rm
# removes the container. Test values only.
set -euo pipefail
: "${REDIS_IMAGE:?set REDIS_IMAGE to the pinned image@sha256 digest}"
exec docker run --rm --network host "$REDIS_IMAGE" redis-server "$@"
