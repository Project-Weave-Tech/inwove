# The one-off rekey image (Security 12422). TEST BUILD on Actions: nothing is pushed or deployed. Built from the same
# commit as the service image. It carries node, @noble/hashes and the SHIPPED store tool (mediator-store-ship.mjs output:
# rekey, opens, names, absent; admin-out, delete-admin and the two test subcommands removed, not disabled). No mediator
# binary, no setup binary, no port, no long-running service: it runs as a job and is gone after the sitting.
FROM node:22-bookworm-slim@sha256:e9f565d32859f0cbfb52125eafe8be39390f24dac302dc3cdf566e8ba3ab21ee
COPY --chmod=0444 mediator-store.mjs /opt/rekey/mediator-store.mjs
COPY node_modules/@noble/hashes /opt/rekey/node_modules/@noble/hashes
USER 1000:1000
ENTRYPOINT ["node", "/opt/rekey/mediator-store.mjs"]
