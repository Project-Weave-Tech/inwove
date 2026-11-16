# The one-off rekey image (Security 12422). TEST BUILD on Actions: nothing is pushed or deployed. Built from the same
# commit as the service image. It carries node, @noble/hashes and the SHIPPED store tool (mediator-store-ship.mjs output:
# rekey, opens, names, absent; admin-out, delete-admin and the two test subcommands removed, not disabled). No mediator
# binary, no setup binary, no port, no long-running service: it runs as a job and is gone after the sitting.
FROM node:22-bookworm-slim@sha256:e9f565d32859f0cbfb52125eafe8be39390f24dac302dc3cdf566e8ba3ab21ee
# The directory first, 0755: BuildKit gives a directory COPY --chmod creates the file's mode (0444, no search bit),
# and the image's user then can't reach the tool (run 43831112703: every call died in node's loader).
# Security 11869.3 (a): apt's logs go in the same RUN, so no layer keeps them (a log has no reason to be in a one-off
# image, and the base's eipp.log.xz is a real xz the archive line would rightly call red).
RUN install -d -m 0755 /opt/rekey /opt/rekey/node_modules /opt/rekey/node_modules/@noble && rm -rf /var/log/apt
COPY --chmod=0444 mediator-store.mjs /opt/rekey/mediator-store.mjs
COPY node_modules/@noble/hashes /opt/rekey/node_modules/@noble/hashes
USER 1000:1000
ENTRYPOINT ["node", "/opt/rekey/mediator-store.mjs"]
