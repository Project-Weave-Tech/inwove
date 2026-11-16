# Re-pinning the mediator: the checklist

A re-pin moves `MED_SHA` / `MED_REF` in `.github/workflows/tsp-library-tests.yml` to a new upstream commit. It reaches
the host only when every step below holds on the new pin, in one job run, and Security has read it.

1. **Fetch by full sha, proven upstream's.** `fetch-pinned.sh` refuses a commit that isn't an ancestor of `MED_REF`.
2. **The environment-read record.** `mediator-env-reads.mjs <checkout> mediator-env-lists.json --write`, in its own
   commit; a new deny name is written `unread` and stays red until Security reads it (condition 16.2(b)).
3. **The resolved features.** Lean build: no `vta*`, no `secrets-*`, no `aws`; the default build (the control) must
   fail. The setup binary: only `vta-sdk`; its tree record is compared with register L8, never rewritten by the job.
4. **The client-keyring path.** Every path to `keyring-core` / the dbus store runs through `affinidi-tdk-common`; no
   `keyutils` crate in either tree.
5. **Admin over TSP is refused with the guard on (expected)** — the `expectred` step, `mediator-expect-red.mjs`
   (Security 12552; Railroad 12567.1; Security 12582.1). **A re-pin whose expect-red doesn't pass stops here, whatever
   else is green, and comes to SECURITY as a finding.** If the TSP update or an add is ever accepted, that is a
   finding, never a test to update.
   Beside it, the known-gap line `tsp_account_add_lands_despite_refusal` (Security 12672.1, upstream report 2): how
   many of the three TSP adds answered a refusal and still landed (by sign-in). At 0.50.0 it is 3/3, **amber, never
   green**. Any other count is a STOP: it comes to SECURITY + RAILROAD as a re-pin note, because the setup job's own
   add path would behave differently. When a re-pin carries upstream's fix, this line is rewritten as a gating
   requirement in the same change.
6. **Every private key of the admin DID, as one admin key** (Security 12582.2): the setup run lists the admin DID
   document's keys, the credential must yield each one, the scan self-hits on each kind in each encoding, and at the
   end no volume file or log line carries any of them and `admin-monitor.json` is gone.
7. **`trust_task_verification = "enforce"`** in the conf the job runs, and the entrypoint refuses any other (Security
   12672.2: the typed literal, exactly once, under `[security]`). At 0.50.0 the upstream default and the shipped
   `conf/mediator.toml` are `warn`, under which every acceptance failure is logged and let through
   (`trust_task_verify.rs:176-187`): a write with no proof on the authcrypt key alone, and a stale or replayed one. The
   behaviour proof is E1 in the DIDComm closed run: an unsigned admin write is refused `proof_required` and doesn't land
   (read back), an unsigned read answers. Re-read the `warn`/`enforce` branch and setup's `config_writer.rs` line at
   each re-pin.
8. **Setup's output stays off every log** (Security 12672.3): setup's stdout+stderr to one tmpfs file, the scan hits
   the key echo there first, then 0 marker lines in the step's own log, every start, and every artifact file; the file
   is gone at the end. If a re-pin drops the echo (upstream report 4), the "must first hit" line turns red: re-read it
   with Security, never loosen it in place.
9. **The rest of the mediator job green**, and the units (`npm test`; `node --test admin-key-markers.test.mjs` here).
10. **The images** (Security 12422 e, 12491 b, 12519 e, 12195.1 d): `mediator-images.sh` builds the service image
    and the one-off rekey image from the same commit and judges both on their whole filesystems (after the same search
    hits a planted tree). The service image holds no `mediator-setup`, no `mediator-store.mjs`, no file carrying
    `rekey`/`delete-admin`/`admin-out`/`seal-test`/`encrypt-test`, no D-Bus daemon/broker/launcher or bus path, and
    names no `DBUS_*`/`XDG_RUNTIME_DIR`. The rekey image's shipped tool has only `rekey`/`opens`/`names`/`absent`;
    its sha256 goes in L8. A hit in a file we didn't put there is a finding for SECURITY, never a word to drop. Both
    base images are pinned by digest; a re-pin re-reads them. (Security 12940:) the shipped tool holds no `getEntry`
    (the one-value open, dropped with `admin-out`; it is on `SHIPPED_FORBIDDEN`), and no file in the rekey image
    outside the shipped path carries `delete-admin`/`admin-out`/`seal-test`/`encrypt-test`, after that search hits
    the planted renamed copy. The service image's own entrypoint, started bare, writes the keyring probe as its first
    stderr line (refused = PASS, landed = AMBER → SECURITY, absent/`probe_failed`/no line = a finding) and still
    refuses 78. The probe never gates a start; the host's dry first start reads the same line.
11. **The conf shapes the entrypoint refuses still match the parser** (Security 12795.2, 12892.3): at each re-pin
    read the mediator's `toml` version in its `Cargo.lock` and `SecurityConfigRaw` (`affinidi-messaging-mediator-config/src/security.rs`).
    The entrypoint refuses `"""`/`'''` anywhere and a `{`/`}` on any non-comment line, because a multi-line string or a
    TOML 1.1 multi-line inline table can hide `trust_task_verification` while the mediator runs `warn`. If the new
    template or setup's writer uses either shape, re-read it with Security; never loosen the refusal in place. If
    upstream adds `deny_unknown_fields` (report 5, ask 4), the brace check stays: it is the tripwire, not the proof.
    If upstream's parser ever accepts bare words in arrays, re-read the section tracker with Security (Security 13044.1:
    an array element line reading `[security]` fools the awk tracker today, and is safe only because TOML refuses the
    bare word, so the mediator won't start). Re-read upstream's `conf/mediator.toml` for braces here too: today it
    rests on the grep plus the green entrypoint step on run `43840858890`.
12. **The rekey image's allowed archives** (Security 11869.3, Railroad 11857): `ARCHIVES_ALLOWED` in
    `mediator-image-check.mjs` holds one triple, `/var/lib/dpkg/alternatives/builtins.7.gz` at its sha256 and size in
    the pinned `node:22-bookworm-slim` (kinds exactly `['by-name']`), and the rekey Dockerfile removes `/var/log/apt`.
    At a base re-pin, read the new base's file at that path (the images step prints `rekey_archives_allowed_read`) and
    any new archive hit, and bring both to SECURITY: the set is re-pinned or widened only by a Security block, never in
    place. A new base where the file is gone keeps the line red-safe (an absent allowed path allows nothing).
13. **The rekey image's base diff** (Security 11869.4): `mediator-base-diff.mjs` walks the rekey image and the pinned
    base (both read from their own saved layers, Security 12430; never `docker export`); every regular file is byte-identical to the base's, same mode and owner, or in
    `rekey-added.json` (the shipped tool at the L8 pin, each `@noble/hashes` file at its sha); added directories only
    under `/opt/rekey`. At a base re-pin, or when `@noble/hashes` or the shipped tool moves, the job prints
    `rekey_added_read`; the new shas come to SECURITY and are re-pinned only by a Security block, never in place.
14. **The base diff's base side is the pinned layers** (Security 12327, 12358; Railroad 12314, 12351):
    `mediator-base-fetch.mjs` fetches every layer the pinned amd64 manifest names; `mediator-base-layers.mjs` checks each
    (compressed sha256 + size, media type, count = `diff_ids`, decompressed sha256 = `diff_ids[i]`) and applies them in
    order (whiteouts, opaque dirs, effective pax/GNU names; an escape or a write through a symlink is red). The local
    pull's saved tree must equal that tree entry for entry, zero exceptions. At a base re-pin the job prints
    `rekey_base_layers` (per-layer verdicts + counts).
15. **Every image is read from its own layers** (Security 12430): `mediator-image-save.mjs` reads each `docker save`
    (one linux/amd64 image, every blob by its digest; layers by `checkLayers`, the same function as item 14; the first
    `diff_ids` = the pinned base's, the service image's against its own FROM chain), judges the ADDED layers one by one
    (nothing added then deleted or overwritten; whiteouts and opaque dirs only of base paths named in
    `ADDED_LAYER_DELETES`, exact both ways: the rekey image `/var/log/apt`, the service image none) and searches every
    file in every added layer's own tar. The config record reads the saved config blob; inspect is evidence and must
    agree. At a base re-pin, or when a Dockerfile adds or removes a delete, the job prints `rekey_save` /
    `service_save` (`whiteouts_seen`, `added_layer_red`); a new delete comes to SECURITY and is listed only by a
    Security block, never in place. The plants (`save_read_plants`) must stay red first.
16. **The service image's base is pinned as a triple** (Security 12480 (2)): `service-base.json` holds the index
    (= `mediator-service.Dockerfile`'s FROM digest), its one linux/amd64 manifest and that manifest's config, read
    against the registry chain by `chainPinVerdict` (`--chain-pins`). The images step's `service_base_pinned` line is
    PASS only when all three equal the chain; a moved FROM with an unmoved pin is FAIL; a `VERIFY` value is STOP, and
    a STOP line fails the step. A new service base comes to SECURITY with the chain's digests (printed as
    `service_save.chain_pins.read`) and is pinned only by a Security block, never in the Dockerfile edit itself. The
    same added-layer rules as item 15 hold, including **one path written twice in one added layer** (Security 12480):
    red as `written_twice_in_one_layer`.
