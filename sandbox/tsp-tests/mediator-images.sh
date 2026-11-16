#!/bin/bash
# The Dockerfile batch (Security 12422 e + the rekey image, 12491 b's image half, 12519 e, 12195.1 d): builds the
# service image and the one-off rekey image from the same commit, on the runner's Docker, and judges both. TEST
# BUILD: nothing is pushed to a registry, nothing deployed; every store and passphrase here is made up and dies with
# the job. Prints names, codes and verdicts only.
#
# Usage: mediator-images.sh <lean mediator binary> <out json>
# Writes beside <out>: service-image.json, rekey-image.json, and <out> (the summary; exit 1 if any line is FAIL).
#   service: the image check (mediator-image-check.mjs service), the binary's libraries all resolve in the image,
#            `mediator --help` runs in it, and the keyring probe as the service user: refused both = PASS,
#            landed = AMBER (the host's syscall filter, never red), anything else FAIL; and (Security 12940) the
#            image's own entrypoint, started bare, writes that probe as its first stderr line and still refuses (78).
#   rekey:   the image check (mediator-image-check.mjs rekey) on the shipped tool; (Security 11869.4) the base diff
#            against the pinned base (mediator-base-diff.mjs, added set rekey-added.json), whose base side (Security
#            12327) is built from the pinned layers (mediator-base-layers.mjs) with the local pull cross-checked
#            against it exactly; in the image, with no network and
#            a read-only root: `rekey` refuses while mediator_admin_credential is in the store, the removed
#            subcommands answer "usage" (exit 2), and after the credential is gone `rekey` re-seals (old no longer
#            opens, new does, same entries).
# Security 12430: every image (service, rekey, the local base pull, the plants) is read from its own `docker save`
# (mediator-image-save.mjs), never through a container: `docker export` is gone from this step. One image for
# linux/amd64 in each save, every blob by its digest, each layer checked by the same function as the registry base,
# the base prefix exact, the added layers judged one by one and searched file by file. The saves and their layer tars
# live only in this step's scratch dir, are deleted at its end and absence-checked; never an artifact.
set -uo pipefail
BIN="$1"; OUT="$2"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ODIR="$(dirname "$OUT")"; mkdir -p "$ODIR"
W="$(mktemp -d "${RUNNER_TEMP:-/tmp}/images.XXXXXX")"
SVC=wpi-mediator-service:test REK=wpi-mediator-rekey:test
COMMIT="$(git -C "$HERE" rev-parse HEAD 2>/dev/null || echo unknown)"
fail() { echo "mediator-images: $1" >&2; exit 1; }

# --- the service image's context: only what the service needs
C="$W/svc"; mkdir -p "$C"
cp "$BIN" "$C/mediator" || fail "no mediator binary"
cp "$HERE/mediator-entrypoint.sh" "$HERE/mediator-deny.sha256" "$C/"
node "$HERE/mediator-deny-file.mjs" "$HERE/mediator-env-lists.json" "$C/deny.txt" > "$W/deny.sha" || fail "deny file"
[ "$(cat "$W/deny.sha")" = "$(tr -d ' \n' < "$HERE/mediator-deny.sha256")" ] || fail "the deny file is not the baked sha256's"
gcc -static -O2 -Wall -o "$C/keyring-probe" "$HERE/keyring-probe.c" || fail "keyring probe build"
docker build -q --label "org.opencontainers.image.revision=$COMMIT" -f "$HERE/mediator-service.Dockerfile" -t "$SVC" "$C" > "$W/svc.id" || fail "service image build"

# --- the rekey image's context: the shipped tool (stripped here, then judged on the image's own copy) + its one dependency
R="$W/rek"; mkdir -p "$R/node_modules/@noble"
node "$HERE/mediator-store-ship.mjs" "$HERE/mediator-store.mjs" "$R/mediator-store.mjs" > "$W/ship.json" || fail "ship strip"
cp "$HERE/mediator-rekey-entrypoint.sh" "$R/rekey-entrypoint.sh" || fail "no rekey entrypoint"
cp -r "$HERE/node_modules/@noble/hashes" "$R/node_modules/@noble/" || fail "no @noble/hashes (npm ci first)"
docker build -q --label "org.opencontainers.image.revision=$COMMIT" -f "$HERE/mediator-rekey.Dockerfile" -t "$REK" "$R" > "$W/rek.id" || fail "rekey image build"

# --- Security 11869.4: the base-diff line; 12430: both sides read from saved layers.
BASE_REF="$(sed -n 's/^FROM \([^ ]*\).*/\1/p' "$HERE/mediator-rekey.Dockerfile" | head -1)"
[[ "$BASE_REF" == *@sha256:* ]] || fail "the rekey Dockerfile's base is not pinned by digest"
SVC_BASE_REF="$(sed -n 's/^FROM \([^ ]*\).*/\1/p' "$HERE/mediator-service.Dockerfile" | head -1)"
[[ "$SVC_BASE_REF" == *@sha256:* ]] || fail "the service Dockerfile's base is not pinned by digest"
CONFIG_PIN="$(node -e 'console.log(JSON.parse(require("fs").readFileSync(process.argv[1], "utf8")).base_config_digest)' "$HERE/rekey-config.json")"
docker image inspect "$SVC" > "$W/svc-inspect.json" && docker image inspect "$REK" > "$W/rek-inspect.json" || fail "inspect"
# Security 11935 (a): the base half of the rekey config record is read from the pinned base itself, pulled by digest
# for linux/amd64, never typed by hand (mediator-image-config.mjs; hand half rekey-config.json).
docker pull -q --platform linux/amd64 "$BASE_REF" > /dev/null && docker image inspect "$BASE_REF" > "$W/base-inspect.json" || fail "base inspect"
# Security 12197.2 + 12232.1: the registry chain the pin names (index by the FROM digest, the one linux/amd64 manifest,
# its config blob), raw, so the config record checks every hash itself and ties inspect's read to the pinned blob. A
# failed fetch is not fatal here: the record reads the missing blob as FAIL, never as a pass.
node "$HERE/mediator-base-fetch.mjs" "$BASE_REF" "$W/base-chain" || echo "mediator-images: base registry chain not fully fetched (the config record and the base layers go red)" >&2
# Security 12430 (d): the service image is not built FROM the rekey pin, so its base gets its own chain, tied by hash to
# its own FROM digest (its layers are judged from the service image's own save).
node "$HERE/mediator-base-fetch.mjs" "$SVC_BASE_REF" "$W/svc-base-chain" --no-layers || echo "mediator-images: service base chain not fetched (the service save read goes red)" >&2
# Security 12327 + 12358: the base diff's base side is built from the layers the pinned manifest names, each checked
# (compressed digest + size, media type, count, decompressed digest = the blob's diff_ids[i]) and applied in order
# (whiteouts, opaque dirs, effective pax/GNU names; an escape or a write through a symlink is red). The tree is written
# only when all of it passes, so a failed fetch or check leaves no tree and the base diff is red.
bl=0; node "$HERE/mediator-base-layers.mjs" "$W/base-chain" "$HERE/rekey-config.json" "$W/base-tree.json" "$ODIR/rekey-base-layers.json" || bl=$?
rm -rf "${W:?}/base-chain/layers"

# --- Security 12430: each image read from its own save. saveread <label> <delete list> <image> <chain> <from digest> [flags]
# writes $W/trees/<label>-tree.json (the applied tree + added-layer files; bytes read back from the layer tars),
# $W/<label>-config.json (the saved config blob) and $ODIR/<label>-save.json (the verdict). The layout goes as soon as it
# is read; the layer tars stay in $W/save until the end of the step.
SAVES="${W:?}/save"; TREES="${W:?}/trees"; mkdir -p "$SAVES" "$TREES"
saveread() {
  local label="$1" kind="$2" img="$3" chain="$4" from="$5"; shift 5
  local L="${SAVES:?}/$label"; mkdir -p "$L/layout"
  docker save --platform linux/amd64 "$img" -o "$L/save.tar" || { echo "mediator-images: $label save failed" >&2; return 1; }
  tar -x -C "$L/layout" --no-same-owner -f "$L/save.tar"; local rc=$?; rm -f "$L/save.tar"; [ $rc = 0 ] || return 1
  node "$HERE/mediator-image-save.mjs" --name "$kind" --layout "$L/layout" --work "$L/layers" --base-chain "$chain" --from-digest "$from" \
    --out-tree "$TREES/$label-tree.json" --out-config "$W/$label-config.json" --out "$ODIR/$label-save.json" "$@"; rc=$?
  rm -rf "${L:?}/layout"
  return $rc
}
BASE_DIGEST="${BASE_REF##*@}"; SVC_BASE_DIGEST="${SVC_BASE_REF##*@}"
# Security 12480 (2): the service base pinned as a triple (service-base.json); its own line, STOP while VERIFY
ss=0; saveread service service "$SVC" "$W/svc-base-chain" "$SVC_BASE_DIGEST" --chain-pins "$HERE/service-base.json" --inspect "$W/svc-inspect.json" || ss=$?
rs=0; saveread rekey rekey "$REK" "$W/base-chain" "$BASE_DIGEST" --config-pin "$CONFIG_PIN" --inspect "$W/rek-inspect.json" || rs=$?
# 12430 (f): the local base pull, saved: its layers = the registry's by digest; its tree = the registry tree, exactly
lb=0; saveread localbase base "$BASE_REF" "$W/base-chain" "$BASE_DIGEST" --config-pin "$CONFIG_PIN" --same-layers-as-chain --inspect "$W/base-inspect.json" || lb=$?

# --- Security 12430 (g): the save read's own plants, each a throwaway image FROM the rekey image, each red first.
#   four:      a 22-byte payload at /etc/hosts, /etc/hostname, /etc/resolv.conf and /.dockerenv: the base diff red on
#              each path by name (an export showed the runtime's placeholders there instead);
#   tool:      a renamed copy of the full store tool added in one layer and deleted in the next: the added-layer rule
#              red (added then whited out) AND the added-layer content search hits it in its own layer;
#   whiteout:  a harmless file added under /opt/rekey and deleted in the next layer: the added-layer rule red;
#   overwrite: a file added, then overwritten with other bytes in the next layer: the added-layer rule red. (Another
#              SIZE on purpose: the store's layer differ compares size + mtime, so same-size bytes copied in the same
#              second give an empty layer, which the rule rightly passes since nothing was shipped.)
PD="${W:?}/plants"; mkdir -p "$PD"
head -c 22 /dev/zero | tr '\0' 'p' > "$PD/payload"; [ "$(wc -c < "$PD/payload")" = 22 ] || fail "plant payload"
cp "$HERE/mediator-store.mjs" "$PD/notes.txt"; printf 'one\n' > "$PD/one"; printf 'two, longer\n' > "$PD/two"
printf 'FROM %s\nCOPY payload /etc/hosts\nCOPY payload /etc/hostname\nCOPY payload /etc/resolv.conf\nCOPY payload /.dockerenv\n' "$REK" > "$PD/four.Dockerfile"
printf 'FROM %s\nUSER 0\nCOPY notes.txt /usr/share/plant/notes.txt\nRUN rm /usr/share/plant/notes.txt\n' "$REK" > "$PD/tool.Dockerfile"
printf 'FROM %s\nUSER 0\nCOPY one /opt/rekey/plant-one\nRUN rm /opt/rekey/plant-one\n' "$REK" > "$PD/whiteout.Dockerfile"
printf 'FROM %s\nCOPY one /opt/rekey/plant-one\nCOPY two /opt/rekey/plant-one\n' "$REK" > "$PD/overwrite.Dockerfile"
PLANTS=(four tool whiteout overwrite)
for k in "${PLANTS[@]}"; do
  docker build -q -f "$PD/$k.Dockerfile" -t "wpi-plant-$k:test" "$PD" > /dev/null || fail "plant $k build"
  saveread "plant-$k" plant "wpi-plant-$k:test" "$W/base-chain" "$BASE_DIGEST" --config-pin "$CONFIG_PIN" > "$W/plant-$k.out"
done

# --- the planted tree: every search must hit each of these first
PL="$W/planted"; mkdir -p "$PL/usr/lib/node" "$PL/usr/local/bin" "$PL/usr/bin" "$PL/run/dbus" "$PL/run/user/10001" "$PL/opt"
cp "$HERE/mediator-store.mjs" "$PL/usr/lib/node/renamed-tool.js"
cp "$HERE/mediator-store.mjs" "$PL/opt/mediator-store.mjs"
# Security 13081.2: a gzip of the full tool, named so only its first bytes say it is an archive
gzip -9nc "$HERE/mediator-store.mjs" > "$PL/usr/lib/node/renamed-tool.bin"
: > "$PL/usr/local/bin/mediator-setup"; : > "$PL/usr/bin/dbus-daemon"; : > "$PL/run/dbus/system_bus_socket"; : > "$PL/run/user/10001/bus"

svc=0; node "$HERE/mediator-image-check.mjs" service "save:$TREES/service-tree.json" "$W/service-config.json" "$PL" "$ODIR/service-image.json" || svc=$?
# The base side is the registry-built tree; the local pull's saved tree is the 12430 (f) cross-check against it.
bd=0; node "$HERE/mediator-base-diff.mjs" "$TREES/rekey-tree.json" "$W/base-tree.json" "$TREES/localbase-tree.json" "$HERE/rekey-added.json" "$PL" "$HERE/mediator-store.mjs" "$ODIR/rekey-base-diff.json" || bd=$?
# The config record reads the rekey image's SAVED config blob (12430 (b)); inspect is compared to it in the save read.
cfg=0; node "$HERE/mediator-image-config.mjs" "$W/rekey-config.json" "$W/base-inspect.json" "$HERE/rekey-config.json" "$HERE/mediator-rekey.Dockerfile" "$W/base-chain" "$ODIR/rekey-config-record.json" || cfg=$?
rek=0; node "$HERE/mediator-image-check.mjs" rekey "save:$TREES/rekey-tree.json" "$W/rekey-config.json" /opt/rekey/mediator-store.mjs "$ODIR/rekey-image.json" "$PL" || rek=$?
# The plants: the four-path one through the base diff, the tool one through the rekey image check's added-layer search.
node "$HERE/mediator-base-diff.mjs" "$TREES/plant-four-tree.json" "$W/base-tree.json" "$TREES/localbase-tree.json" "$HERE/rekey-added.json" "$PL" "$HERE/mediator-store.mjs" "$ODIR/plant-four-base-diff.json" > /dev/null 2>&1
node "$HERE/mediator-image-check.mjs" rekey "save:$TREES/plant-tool-tree.json" "$W/plant-tool-config.json" /opt/rekey/mediator-store.mjs "$ODIR/plant-tool-image.json" "$PL" > /dev/null 2>&1
# 12430 (h): the saves, their layer tars, the plants' context and the trees that point into the tars go now; absence checked.
rm -rf "${SAVES:?}" "${TREES:?}" "${PD:?}"; for k in "${PLANTS[@]}"; do docker image rm -f "wpi-plant-$k:test" > /dev/null 2>&1; done
saves_gone=true; for d in "$SAVES" "$TREES" "$PD"; do [ -e "$d" ] && saves_gone=false; done

# --- the service binary in its image: libraries resolve, it runs
ldd_out="$(docker run --rm --network none --entrypoint /usr/bin/ldd "$SVC" /opt/mediator/mediator 2>&1)"; ldd_rc=$?
missing="$(printf '%s\n' "$ldd_out" | grep -c 'not found' || true)"
help=0; docker run --rm --network none --read-only --entrypoint /opt/mediator/mediator "$SVC" --help > /dev/null 2>&1 || help=$?

# --- 12519 (e): the kernel-keyring probe, as the service user, inside the image, under the runner's Docker defaults
probe="$(docker run --rm --network none --read-only --entrypoint /opt/mediator/keyring-probe "$SVC" 2>/dev/null)"; probe_rc=$?
probe_v="$(printf '%s' "$probe" | node -e '
  let s = ""; process.stdin.on("data", (d) => (s += d)).on("end", () => {
    let j; try { j = JSON.parse(s); } catch { console.log("FAIL"); return; }
    const both = [j.session, j.user];
    if (j.uid === 0) console.log("FAIL");
    else if (both.every((x) => x === "refused")) console.log("PASS");
    // Security 13081.3: every label that reads landed must carry its own <label>_removed: true
    else if (both.every((x) => x === "refused" || x === "landed") && ["session", "user"].every((l) => j[l] !== "landed" || j[l + "_removed"] === true)) console.log("AMBER");
    else console.log("FAIL");
  });')"

# --- Security 12940: the same probe through the image's OWN entrypoint, started with no arguments (it refuses
# "missing --bin" after the probe, so nothing else runs). Its first stderr line must be the probe's JSON line:
# refused = PASS, landed = AMBER, anything else (no line, absent, probe_failed) = FAIL, and the start still refuses 78.
ep_rc=0; ep_err="$(docker run --rm --network none --read-only "$SVC" 2>&1 > /dev/null)" || ep_rc=$?
ep_first="$(printf '%s\n' "$ep_err" | head -1)"
ep_v="$(printf '%s' "$ep_first" | node -e '
  let s = ""; process.stdin.on("data", (d) => (s += d)).on("end", () => {
    let j; try { j = JSON.parse(s); } catch { console.log("FAIL"); return; }
    if (j.entrypoint !== "keyring_probe") console.log("FAIL");
    else if (j.verdict === "refused" && j.l8 === "PASS") console.log("PASS");
    else if (j.verdict === "landed" && j.l8 === "AMBER") console.log("AMBER");
    else console.log("FAIL");
  });')"
[ "$ep_rc" = 78 ] || ep_v=FAIL

# --- the rekey image's behaviour, on a made-up store (the full source tool writes it here, on the runner, never in the image)
D="$W/rekey-data"; PP="$(mktemp -d /dev/shm/rekeypp.XXXXXX)"; mkdir -p "$D"; chmod 0700 "$D" "$PP"
head -c 24 /dev/urandom | base64 > "$PP/old"; head -c 24 /dev/urandom | base64 > "$PP/new"; chmod 0444 "$PP/old" "$PP/new"
node "$HERE/mediator-store.mjs" seal-test "$D/secrets.json" "$PP/old" '{"mediator_secrets":"made-up","mediator_jwt_secret":"made-up","mediator_admin_credential":"{\"did\":\"did:key:zMadeUp\"}"}' > /dev/null || fail "made-up store"
# The tool's own subcommands are called past the entrypoint (by node, by path); `rekey` itself only through the image's
# entrypoint (Security 12024.1), with the two passphrases as service variables and planted service markers beside them.
rrun() { docker run --rm --network none --read-only --user "$(id -u):$(id -g)" -v "$D:/data" -v "$PP:/run/pp:ro" --entrypoint /usr/local/bin/node "$REK" /opt/rekey/mediator-store.mjs "$@"; }
MK_DB="marker-db-$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')"; MK_RD="marker-redis-$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')"
erun() { docker run --rm --network none --read-only --user "$(id -u):$(id -g)" -v "$D:/data" \
  -e DATABASE_URL="postgres://u:$MK_DB@h/db" -e REDIS_PASSWORD="$MK_RD" \
  -e ENKARA_MEDIATOR_BACKEND_PASSPHRASE="$(cat "$PP/old")" -e ENKARA_MEDIATOR_BACKEND_PASSPHRASE_NEW="$(cat "$PP/new")" \
  "$REK" --volume /data --tmpfs /dev/shm; }
# Each call's exit and the first line it wrote to stderr (the tool prints names and verdicts only; a docker or node
# failure shows here instead of as a bare FAIL). Cut to 160 characters, JSON-escaped by node.
CALLS="$W/rekey-calls.jsonl"; : > "$CALLS"
note() { node -e 'const [c, x, e] = process.argv.slice(1); console.log(JSON.stringify({ call: c, exit: Number(x), stderr: (e.split("\n").find(Boolean) || "").slice(0, 160) }))' "$1" "$2" "$3" >> "$CALLS"; }
r1=0; r1_err="$(erun 2>&1 > /dev/null)" || r1=$?
note rekey-with-credential "$r1" "$(printf '%s\n' "$r1_err" | grep -v '^rekey-entrypoint:')"
r1_names_cred=$([[ "$r1_err" == *mediator_admin_credential* ]] && echo true || echo false)
removed=(); for s in admin-out delete-admin seal-test encrypt-test; do c=0; e="$(rrun "$s" /data/secrets.json /run/pp/old 2>&1 > /dev/null)" || c=$?; note "$s" "$c" "$e"; removed+=("\"$s\":$c"); done
node "$HERE/mediator-store.mjs" delete-admin "$D/secrets.json" "$PP/old" > /dev/null || fail "made-up store delete"
r2=0; r2_out="$(erun 2>"$W/r2.err")" || r2=$?; note rekey-after-delete "$r2" "$(grep -v '^rekey-entrypoint: env -i dropped' "$W/r2.err")"
# Security 12024.1: no marker value on either stream of either run; the tool past `env -i` refuses any other name, so
# its exit 0 is the proof the markers never reached it. 12024.2 (a): a second run refuses and leaves the store as it was.
markers=0; for v in "$MK_DB" "$MK_RD" "$(cat "$PP/old")" "$(cat "$PP/new")"; do
  [[ "$r1_err$r2_out$(cat "$W/r2.err")" == *"$v"* ]] && markers=$((markers + 1)); done
dropped_db=$(grep -c '^rekey-entrypoint: env -i dropped .*DATABASE_URL' "$W/r2.err" || true)
pre3="$(sha256sum < "$D/secrets.json")"; r3=0; e="$(erun 2>&1 > /dev/null)" || r3=$?; note rekey-second-run "$r3" "$(printf '%s\n' "$e" | grep -v '^rekey-entrypoint:')"
same3=$([ "$(sha256sum < "$D/secrets.json")" = "$pre3" ] && echo true || echo false)
o_old=0; e="$(rrun opens /data/secrets.json /run/pp/old 2>&1 > /dev/null)" || o_old=$?; note opens-old "$o_old" "$e"
o_new=0; e="$(rrun opens /data/secrets.json /run/pp/new 2>&1 > /dev/null)" || o_new=$?; note opens-new "$o_new" "$e"
rm -rf "$PP"; [ -e "$PP" ] && fail "passphrase dir still there"

# --- 12430 (g): each plant red for its own reason, every other save line still PASS (names, kinds and paths only)
node - "$ODIR" "$W/plants.json" <<'JS'
const fs = require('fs'); const [odir, out] = process.argv.slice(2);
const rd = (f) => { try { return JSON.parse(fs.readFileSync(f, 'utf8')); } catch { return null; } };
const others = (v, but) => !!v && Object.entries(v.checks).every(([k, x]) => but.includes(k) || x === 'PASS');
const layerRed = (v, kind, gone) => !!v && !v.ok && v.checks.added_layers_clean === 'FAIL' && others(v, ['added_layers_clean'])
  && v.added_layer_red.some((r) => r.kind === kind && (r.gone === gone || `/${r.path}` === gone));
const four = rd(odir + '/plant-four-save.json'), fourBd = rd(odir + '/plant-four-base-diff.json');
const tool = rd(odir + '/plant-tool-save.json'), toolImg = rd(odir + '/plant-tool-image.json');
const wh = rd(odir + '/plant-whiteout-save.json'), ov = rd(odir + '/plant-overwrite-save.json');
const FOUR = ['/etc/hosts', '/etc/hostname', '/etc/resolv.conf', '/.dockerenv'];
const TOOL = '/usr/share/plant/notes.txt', ONE = '/opt/rekey/plant-one';
const per = {
  four_paths_red_by_name: !!four && four.ok && !!fourBd && fourBd.checks.rekey_matches_base_plus_added_set === 'FAIL' && FOUR.every((p) => fourBd.red_paths.includes(p)),
  tool_added_then_deleted_red: layerRed(tool, 'added_then_whited_out', TOOL),
  tool_found_in_its_own_layer: !!toolImg && toolImg.checks.added_layers_no_file_carries_the_removed_words === 'FAIL' && (toolImg.added_layer_removed_word_hits || []).some((h) => h.path === TOOL),
  whiteout_of_an_added_path_red: layerRed(wh, 'added_then_whited_out', ONE),
  overwrite_of_an_added_file_red: layerRed(ov, 'added_then_overwritten', ONE),
};
const rec = { bites: Object.values(per).every(Boolean), per,
  four_red_paths: fourBd ? fourBd.red_paths.filter((p) => FOUR.includes(p)) : null,
  layer_red: Object.fromEntries([['tool', tool], ['whiteout', wh], ['overwrite', ov]].map(([k, v]) => [k, v ? v.added_layer_red.map((r) => ({ kind: r.kind, layer: r.layer, gone: r.gone ?? `/${r.path}` })) : null])) };
fs.writeFileSync(out, JSON.stringify(rec));
JS

node - "$OUT" "$ODIR" "$W" <<EOF
const fs = require('fs'); const [out, odir, w] = process.argv.slice(2);
const rd = (f) => { try { return JSON.parse(fs.readFileSync(f, 'utf8')); } catch { return null; } };
const svc = rd(odir + '/service-image.json'), rek = rd(odir + '/rekey-image.json'), ship = rd(w + '/ship.json'), bdiff = rd(odir + '/rekey-base-diff.json'), blay = rd(odir + '/rekey-base-layers.json');
const svs = rd(odir + '/service-save.json'), rks = rd(odir + '/rekey-save.json'), lbs = rd(odir + '/localbase-save.json'), plants = rd(w + '/plants.json');
const removed = JSON.parse('{${removed[*]}}'.replace(/ /g, ','));
let r2 = null; try { r2 = JSON.parse(\`$r2_out\`); } catch {}
const P = (b) => (b ? 'PASS' : 'FAIL');
const lines = {
  service_image_check: P(svc && svc.ok),
  service_libraries_resolve: P($ldd_rc === 0 && $missing === 0),
  service_mediator_help_runs: P($help === 0),
  service_keyring_probe: '$probe_v' || 'FAIL',
  service_entrypoint_first_line_is_the_keyring_probe: '$ep_v' || 'FAIL',
  service_saved_layers: P($ss === 0 && svs && svs.ok),
  service_base_pinned: (svs && svs.chain_pins && svs.chain_pins.verdict) || 'FAIL',
  rekey_image_check: P(rek && rek.ok),
  rekey_saved_layers: P($rs === 0 && rks && rks.ok),
  local_base_saved_layers_are_the_registry_layers: P($lb === 0 && lbs && lbs.ok),
  save_read_instrument_bites: P(plants && plants.bites),
  saves_removed: P('$saves_gone' === 'true'),
  rekey_base_layers: P($bl === 0 && blay && blay.ok),
  rekey_base_diff: P($bd === 0 && bdiff && bdiff.ok),
  rekey_refuses_while_admin_credential_present: P($r1 !== 0 && $r1_names_cred),
  rekey_removed_subcommands_answer_usage: P(Object.values(removed).length === 4 && Object.values(removed).every((c) => c === 2)),
  rekey_config_record: P($cfg === 0),
  rekey_env_i_no_marker_reaches_tool_or_output: P($r2 === 0 && $markers === 0 && $dropped_db === 1),
  rekey_second_run_refuses_store_unchanged: P($r3 === 1 && $same3),
  rekey_reseals_once_credential_gone: P($r2 === 0 && r2 && r2.values_unchanged && r2.salt_changed && !r2.old_opens && r2.new_opens && $o_old === 4 && $o_new === 0),
};
const rec = {
  what: 'Dockerfile batch: service image + one-off rekey image (Security 12422 e, 12491 b, 12519 e, 12195.1 d)',
  commit: '$COMMIT', lines,
  service_image_id: fs.readFileSync(w + '/svc.id', 'utf8').trim(), rekey_image_id: fs.readFileSync(w + '/rek.id', 'utf8').trim(),
  shipped_tool_sha256: rek && rek.shipped_sha256, ship_strip_sha256: ship && ship.sha256,
  keyring_probe: (() => { try { return JSON.parse(\`$probe\`); } catch { return null; } })(), keyring_probe_host: 'GitHub ubuntu-latest runner, Docker default seccomp',
  entrypoint_probe_line: (() => { try { return JSON.parse(\`$ep_first\`); } catch { return null; } })(), entrypoint_exit: $ep_rc,
  removed_subcommand_exits: removed,
  rekey_calls: fs.readFileSync(w + '/rekey-calls.jsonl', 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l)),
};
fs.writeFileSync(out, JSON.stringify(rec, null, 2) + '\n');
console.log(JSON.stringify(lines));
console.log(JSON.stringify(rec.rekey_calls));
// Security 13081.1: the shipped tool's sha256 in the log too, so it can be read against the L8 pin without the artifact
console.log(JSON.stringify({ shipped_tool_sha256: rec.shipped_tool_sha256, ship_strip_sha256: rec.ship_strip_sha256, rekey_archive_hits: rek && rek.archive_hits, rekey_archives_allowed_read: rek && rek.archives_allowed_read }));
// Security 11869.4: the base diff's verdict, and what the image added (path, sha256, mode, owner), once, for the pin
// Security 12327.6: per-layer digest verdicts and counts only
console.log(JSON.stringify({ rekey_base_layers: blay && { ok: blay.ok, checks: blay.checks, layers: blay.layers, counts: blay.counts, apply_red: blay.apply_red } }));
console.log(JSON.stringify({ rekey_base_diff: bdiff && { ok: bdiff.ok, checks: bdiff.checks, instrument: bdiff.instrument, changed: bdiff.changed, red_paths: bdiff.red_paths, added_file_not_in_set: bdiff.added_file_not_in_set, added_dir_outside: bdiff.added_dir_outside, added_not_a_file: bdiff.added_not_a_file, added_setuid: bdiff.added_setuid, added_set_missing: bdiff.added_set_missing, deleted_base_entries: bdiff.deleted_base_entries } }));
// Security 12430 (f): the local pull's saved tree against the registry-built tree, zero exceptions
console.log(JSON.stringify({ rekey_base_cross_check: bdiff && { checks: bdiff.checks && { local_base_equals_registry_tree: bdiff.checks.local_base_equals_registry_tree, cross_check_bites: bdiff.checks.cross_check_bites }, only_local: bdiff.cross_check.only_local, only_registry: bdiff.cross_check.only_registry, differ: bdiff.cross_check.differ, entries: { rekey: bdiff.rek_entries, local_base: bdiff.local_base_entries, registry: bdiff.registry_entries } } }));
// Security 12430 (b)-(e), (g): each save read, per layer (counts per kind), the added-layer reds, the plants
const sv = (v) => v && { ok: v.ok, checks: v.checks, chain_pins: v.chain_pins, image: v.image, attestations: (v.attestations_in_save || []).length, base_chain: v.base_chain, per_layer: v.per_layer, counts: v.counts, added_layer_red: v.added_layer_red, apply_red: v.apply_red, whiteouts_seen: v.added_layer_whiteouts_seen, inspect_differ: v.inspect_vs_saved_config_differ, save_bad: v.save_bad };
console.log(JSON.stringify({ service_save: sv(svs) }));
console.log(JSON.stringify({ rekey_save: sv(rks) }));
console.log(JSON.stringify({ local_base_save: sv(lbs) }));
console.log(JSON.stringify({ save_read_plants: plants, service_added_layer_hits: svc && svc.added_layer_hits, rekey_added_layer_hits: rek && { removed_words: rek.added_layer_removed_word_hits, archives: rek.added_layer_archive_hits, files: rek.added_layer_files } }));
console.log(JSON.stringify({ rekey_added_read: bdiff && bdiff.added_read }));
// Security 11935 (a), (e), 12197.2 (c), 12232.1: the base's manifest and config digests read from the registry chain
// (for the L8 pins), inspect's Id as evidence only, and the base half beside the verdict
const crec = rd(odir + '/rekey-config-record.json');
console.log(JSON.stringify({ rekey_config_record: crec && { ok: crec.ok, checks: crec.checks, base_manifest_digest_read: crec.base_manifest_digest_read, base_config_digest_read: crec.base_config_digest_read, base_inspect_id: crec.base_inspect_id, base_platform: crec.base_platform, base_half: crec.base_half, details: crec.details } }));
// a STOP line (a pin Security has not written yet) never passes the step
process.exit(Object.values(lines).some((v) => v === 'FAIL' || v === 'STOP') ? 1 : 0);
EOF
