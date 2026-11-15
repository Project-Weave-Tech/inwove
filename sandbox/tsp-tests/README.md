# ref/09: TSP 1.0 library and mediator tests

Railroad's spec `ref/09` (TSP 1.0 + mediator, for Enkara's L8 door), run by `.github/workflows/tsp-library-tests.yml`
on a push to `claude/wpi-build-tsp-**` or by dispatch. Test values only: every key and DID is made inside the job and
thrown away with it (the frames file holding them is deleted before the results are uploaded). No secret, no deploy,
no outside mediator. Not part of the app: its own `package.json`, nothing in the room imports it.

| file | job | what |
|---|---|---|
| `check-pins.mjs`, `pins.json` | audit | versions, licences (an `@openvtc` package not Apache-2.0/MIT fails), full shas of the pinned sources |
| `audit.mjs` | audit | `npm audit --omit=dev`, `cargo audit` on `rs/Cargo.lock`, vti-tsp-js loads in plain Node 22 |
| `rs/` | all | the Rust peer: affinidi-tsp 0.3.0 driven by JSON lines on stdin (`cargo build --locked --release`) |
| `lib.mjs` | all | test VIDs (did:key), a messaging/ping/0.2 Trust Task with an eddsa-jcs-2022 proof, the byte-concatenated binding envelope |
| `vectors.mjs` | vectors | §2.2: every Appendix A vector at `ccda6b33`: version code, opened by TS and by Rust, body as the vector, TS rebuilds byte for byte where the vector gives `ikmE`; sealed-box and post-quantum vectors recorded as answers |
| `roundtrip.mjs` | roundtrip | §2.3: TS→Rust and Rust→TS with the envelope; invite/accept; application frames with and without a relationship |
| `tamper.mjs` | roundtrip | §2.5 (a)–(j); (f) uses a real Rev 3 frame from `@openvtc/vti-tsp-js` 0.3.0 (aliased `vti-tsp-js-rev3`) |
| `netwatch.mjs` | roundtrip | §2.6 roundtrip half: roundtrip inside `unshare -n`, proving the namespace had no network |
| `report.mjs` | report | the §3 markdown report; red while any §0 line has no result |

`mediator-probe.mjs` is the first cut of `mediator` steps 1-2 (open mode, not in the workflow yet): B sends A a
routed frame over `POST /inbound`, A signs in over TSP (`/authenticate/challenge` + `/tsp/authenticate`) and collects
by REST `/fetch`, opens it, deletes it, and fetches again to show it gone. Run against a local mediator 0.50.0 at
`34bbdea4` with `GLOBAL_DEFAULT_ACL=DENY_ALL,LOCAL,SEND_MESSAGES,RECEIVE_MESSAGES,MODE_EXPLICIT_DENY`.

`mediator-line-d.sh` is line D (Security 11528, Railroad 11542), both side by side: a random marker Redis
password; the mediator started at the default (`info`, no `RUST_LOG`) and with
`RUST_LOG=info,affinidi_messaging_mediator::common::config=warn`, each in text and JSON logs, right and wrong password;
it counts every stdout + stderr line carrying the marker and prints only counts. Local run 2026-11-15 against 0.50.0 @
`34bbdea4`, valkey 7.2.13: default FAIL (1 line, the start-up config dump, target
`affinidi_messaging_mediator::common::config`), filter 0 lines in text and JSON, right password starts, wrong exits 1,
no WARN/ERROR line carries a password.

`mediator-acl.mjs` is line C and the inbox-mode pair (Railroad 11542): closed mode (`explicit_allow`), forwarding off,
`trust_task_verification = "enforce"`; the upstream TEST-ONLY admin key registers A, B, D with a signed
`messaging/account/add` over TSP (A as `explicitDeny` + `selfManageList`); A puts D on its deny list with
`messaging/access-list/update`. Local run 2026-11-15: unknown DID refused at the challenge (25); B → A lands and opens;
D → A refused (403, 73 `delivery.refused`); a frame routed to a did:key outside refused (404, 58), which does not yet
prove forwarding-off is the reason (a did:key has no endpoint).
Added after Railroad 11571, run 2026-11-15 ~22:00Z (cloud, 0.50.0 @ `34bbdea4`, valkey 7.2.13): R1, a deliberate
plain-DID `account/add` that the setup check (a real sign-in + an empty `/fetch`, never the add's answer) must turn
red, beside the hashed add passing it; and `--closed-default`, the mediator's default for new accounts explicit-allow
and the admin account's list set to exactly the mediator's own DID hash and read back with `access-list/list` (S2).
- Without the flag: PASS. R1 red as it should be: the plain-DID add is answered `#response`, then the DID is refused
  at the challenge; the hashed add passes the check.
- With `--closed-default`: FAIL, and not for the reason expected. The admin's `access-list/update` and
  `access-list/list` on its own hash are refused before they run (`not permitted to access the access list`), so the
  list stays empty and every later answer to the admin is refused (73); the adds themselves still take effect (A, B, D
  sign in) but are never confirmed. Cause, from source: over TSP the mediator passes the bare sender VID (no `#key`
  fragment, `messages/inbound.rs` `dispatch_tsp_trust_task`), and with `block_remote_admin_msgs = true`
  `common/authz.rs` `check_admin_signature` needs `did#fragment`, so every admin call that goes through
  `check_permissions` (access-list update/list, account get/update/remove, acl get) is refused over TSP. `account/add`
  doesn't go through it, which is why adds work. The same happens with the explicit-deny default (checked).
- Diagnostic only, not a proposed setting: with `block_remote_admin_msgs = false` the `--closed-default` run PASSES
  (admin list = mediator only, count 1, read back; all three adds confirmed; R1 red; C1-C4 as before).
- Line A (Railroad 11506), added in the same session: a did:peer:2 with only an Ed25519 key (no X25519
  `keyAgreement`), registered by its hash, is refused at `/tsp/authenticate` (400, 28 `authentication.tsp.resolve`);
  the control, the same shape with the X25519 key added, signs in. Passes in both runs.

Not built yet (the report shows each as not passed): `mediator` (Affinidi mediator in Docker, REST pickup, Security's lines A–D), and netwatch's mediator egress log.

Run locally: `npm ci --ignore-scripts` here, `cargo build --locked --release --manifest-path rs/Cargo.toml`, then
`node vectors.mjs results <tswg-tsp-specification>/spec/spec.md && node roundtrip.mjs results && node tamper.mjs results && sudo unshare -n -- node netwatch.mjs results`.
Added after Railroad 11606 (written 2026-11-15 ~22:30Z, NOT yet run: the cloud session's permission check refused
`cargo build` of the mediator): step 0, Z1 (a signed-in ordinary account sends `account/add` for a fresh DID's hash:
pass = refused and the fresh DID can't sign in) and Z2 (a DID with no account: no sign-in, and a signed `account/add`
frame to `/inbound` with no token refused). From source, 0.50.0 @ `34bbdea4`: the guard is
`messages/protocols/trust_tasks.rs` `consume_account_add` (`mediator_acl_mode == ExplicitAllow && !is_admin`, the
session's account type), with the sender bound to the session DID by `force_session_did_match` (`messages/inbound.rs`);
in `explicit_deny` mode any signed-in account may add. Z3 is a recorded finding, not a pass line: `account/add` on an
existing hash overwrites its role (to Standard) and ACLs (redis `store/redis/database/accounts.rs` `account_add`, no
existence check).
