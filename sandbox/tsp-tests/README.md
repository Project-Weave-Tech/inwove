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

Not built yet (the report shows each as not passed): `mediator` (Affinidi mediator in Docker, REST pickup, Security's lines A–D), and netwatch's mediator egress log.

Run locally: `npm ci --ignore-scripts` here, `cargo build --locked --release --manifest-path rs/Cargo.toml`, then
`node vectors.mjs results <tswg-tsp-specification>/spec/spec.md && node roundtrip.mjs results && node tamper.mjs results && sudo unshare -n -- node netwatch.mjs results`.
