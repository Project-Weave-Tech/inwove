# The mediator's service image (Security 12195.1, 12422 e, 12491 b). TEST BUILD on Actions: nothing here is pushed to a
# registry or deployed. It holds only what the running service needs: the lean mediator binary built in the same job
# at the pin, the entrypoint, the deny file and its baked sha256, and the keyring probe (12519 e). Never the setup
# binary, never the store tool, never a D-Bus daemon or broker. The base matches the job's runner (the binary is built
# there), pinned by digest. The context is assembled by mediator-images.sh, never the repository root.
FROM ubuntu:24.04@sha256:73b999393d07f2bf65a40373778a44dc9a6d54ad7718d29247d8ff9413c4d6a8
# The runtime libraries the binary links (the job's ldd check fails on any "not found"). libdbus-1-3 is the client
# library only (no daemon): the lean tree links dbus-secret-service via affinidi-tdk-common (12491 a).
RUN apt-get update -q && apt-get install -y --no-install-recommends ca-certificates libssl3t64 libdbus-1-3 \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin mediator \
 && install -d -o 10001 -g 10001 -m 0700 /work /data
COPY --chmod=0555 mediator /opt/mediator/mediator
COPY --chmod=0555 mediator-entrypoint.sh /opt/mediator/mediator-entrypoint.sh
COPY --chmod=0444 mediator-deny.sha256 deny.txt /opt/mediator/
COPY --chmod=0555 keyring-probe /opt/mediator/keyring-probe
USER 10001:10001
WORKDIR /work
ENTRYPOINT ["/bin/bash", "-p", "/opt/mediator/mediator-entrypoint.sh"]
