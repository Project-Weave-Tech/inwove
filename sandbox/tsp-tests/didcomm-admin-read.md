<!-- Source read of the mediator at 0.50.0 @ 34bbdea4, for the DIDComm admin path (Railroad 11606 (a), binding 1). Written by a helper from source only, nothing run against a live mediator; spot-checked by WPI-BUILD: common/authz.rs:189-196 check_admin_signature (kid has "#" and its DID is the session account; the kid is the JWS signer or else the authcrypt sender key, so authcrypt from the admin DID passes). Paths relative to crates/affinidi-messaging-mediator/ in a checkout of that pin. -->
# Mediator v0.50.0 (34bbdea) — DIDComm admin path, source read

Paths below are relative to `crates/affinidi-messaging-mediator/` (call it M) in the checkout at
a checkout of that pin.
The mediator SDK crate (`affinidi_messaging_sdk`, which owns the `MessageType` enum parse) is NOT in this
checkout, so the exact string->enum map is not read; only mediator-side uses are cited.

## 1. How DIDComm is received, and sign-in

Routes (M/src/handlers/mod.rs:43-110), all under `api_prefix` (default `/mediator/v1`, helpers.rs:400-413):
- `POST /inbound` (mod.rs:73-76) -> `message_inbound_handler`. Auth = JWT Bearer (`MaybeSession`, message_inbound.rs:74).
  No content-type check at all: body is read as raw `Bytes` (message_inbound.rs:72-76). The kit's `application/tsp` is not
  required; for DIDComm send the JWE JSON (any content-type; the SDK uses `application/json`).
- `POST /authenticate/challenge` (mod.rs:79-82), shared by DIDComm and TSP. `POST /authenticate` (mod.rs:90), `POST /authenticate/refresh` (mod.rs:91-93) are DIDComm only (`feature = "didcomm"`). TSP uses `POST /tsp/authenticate` (mod.rs:106-109).
- `GET /ws` (mod.rs:59) is the websocket; `/fetch` (mod.rs:50) `/outbound` `/list/..` `/delete` also need the JWT.
- Dispatch in `/inbound` (message_inbound.rs): needs `SEND_MESSAGES` in session ACL (:78); TSP sniff (:128 `affinidi_tsp::is_tsp`);
  DIDComm v1 sniff (:166); else parse as JWE `InboundMessage {protected, recipients[{header{kid},encrypted_key}], iv, ciphertext, tag}`
  (message_inbound.rs:55-67, parse at :257) -> `handle_inbound` -> `handle_inbound_didcomm` (messages/inbound.rs:71-99, :1019).
- In `handle_inbound_didcomm`: `MetaEnvelope::new` (inbound.rs:1046) takes `to_did` from the first recipient `kid` DID part
  (didcomm_compat.rs:88-98). If `to_did == config.mediator_did` (inbound.rs:1071) the mediator unpacks and processes it. Any other `to_did`
  is direct delivery to a local account (inbound.rs:1176+), gated by `local_direct_delivery_allowed` (:1178). So an admin message
  must be a JWE whose recipient kid's DID is exactly the mediator DID.
- After unpack: blocks fully anonymous if `block_anonymous_outer_envelope` (inbound.rs:1102-1118); `authenticated_sender` check
  (:1122, defined messages/mod.rs:59-90); and with `force_session_did_match && session.authenticated`
  (inbound.rs:1131-1136, fn at :1402-1428) the sender kid's DID (`sign_from` else `encrypted_from_kid`) must `same_account` as the session DID
  (error `authorization.did.session_mismatch`). Then `msg.process` (:1139) and the reply is stored for the sender.
- Response of `/inbound` is `SuccessResponse{session_id,http_code,error_code,error_code_str,message,data}` (message_inbound.rs:285-298).
  The admin Trust Task answer is NOT in that body; the mediator packs it to the sender and stores it (trust_tasks.rs:166-182,
  `store_message: true`), so collect it via `/fetch`, WS or pickup, same as the kit does for TSP.

### Sign-in for DIDComm vs TSP (same challenge, different proof)
Step 1 (both): `POST {prefix}/authenticate/challenge`, body JSON `{"did": "did:..."}` (`ChallengeBody`, handlers/authenticate/mod.rs:~60;
handler challenge.rs:24-27). Must start with `did:` else 400 (:29-42). Unknown DID under `explicit_allow` -> 403 `authentication.blocked`
(challenge.rs:76-100); under `explicit_deny` it is auto-registered with `global_acl_default` (:102-111).
Response: `SuccessResponse<AuthenticationChallenge>` -> `data: {"challenge": "<32 alnum>", "session_id": "<12 alnum>"}`
(challenge.rs:119-148; struct mod.rs:32-37).

Step 2 DIDComm: `POST {prefix}/authenticate`, body = a JWE (`InboundMessage`, response.rs:28). Requirements (response.rs):
- JWE must be authcrypt (`alg` contains "1PU", didcomm_compat.rs:122-131) AND encrypted: "signed" here means authenticated=authcrypt
  (response.rs:73-98; also helpers.rs:46-86 `unpack_auth_message` requires `unpack_metadata.authenticated && encrypted`). A separate JWS is NOT required.
- Inner plaintext `from` must equal the envelope `skid` DID (response.rs:~170-190); `type` must be
  `https://affinidi.com/atm/1.0/authenticate` (parsed to `MessageType::AffinidiAuthenticate`, response.rs:195-205; URI confirmed in
  discover_features.rs:158 and tests/message_builders.rs:28); `expires_time` is REQUIRED and in the future (response.rs:225-262);
  `body = {"challenge": ..., "session_id": ...}` (response.rs:265-281); `from` must match the DID from step 1 (:296-318).
  Example from tests/message_builders.rs:18-32: `Message::build(uuid, ".../atm/1.0/authenticate", {challenge,session_id}).to(mediator_did).from(actor_did).created_time(now).expires_time(now+60)`.
Response: `SuccessResponse<AuthorizationResponse>`, `data: {"access_token","access_expires_at","refresh_token","refresh_expires_at"}`
(response.rs:363-370, 415-425). JWT is EdDSA, `aud:"ATM"`, `sub:<did>`, `session_id`, `exp` (helpers.rs:~100-125). Send as
`Authorization: Bearer <access_token>`. Refresh: `POST /authenticate/refresh` with a JWE too (refresh.rs:28), rotated one-time refresh token (mod.rs:38-60).
`_register_did_and_setup` (response.rs:~430) is a backstop account creation after authenticate.

Step 2 TSP (for contrast): `POST /tsp/authenticate` JSON `{vid, session_id, signature}` where signature = Ed25519 over the challenge (tsp.rs:32-46;
matches the kit's `signIn`). Returns the same `AuthorizationResponse`.

## 2. How admin operations are addressed over DIDComm

NOT a separate mediator-administration protocol. Admin = Trust Tasks, identical task documents to TSP, wrapped in one DIDComm binding envelope:
- trust_tasks.rs:1-10 and :55 `ENVELOPE_TYPE = "https://trusttasks.org/binding/didcomm/0.1/envelope"`. DIDComm plaintext `type` = that URI;
  `body` = the COMPLETE Trust Task document (trust_tasks.rs:121-142 `serde_json::from_value(message.body)`).
- The former `https://didcomm.org/mediator/1.0/*` admin/account/ACL protocols are NOT served: refused as unknown (docs/didcomm-protocols.md:~296-299).
  Dispatch arm: messages/mod.rs:164-166 `SDKMessageType::TrustTaskEnvelope => trust_tasks::process`. Unknown `type` -> 501 `me.not_implemented` (mod.rs:240-251).
- The TSP binding differs only in carrier: TSP sends the BARE document (no envelope; inbound.rs:~465-480, `parse_if_served`); DIDComm wraps it in the envelope.
  The kit's `envelope()` in lib.mjs is the TSP-binding one (`.../binding/tsp/0.1/envelope`), unused by mediator-acl.mjs `task()` (which packs the bare doc). Not applicable to DIDComm.

Served task type URIs (served_tasks! macro, trust_tasks.rs:540-565; versions in trust-tasks.toml; URI shape from bundles `typeUri`):
`https://trusttasks.org/spec/<slug>/0.1`, slugs: `messaging/ping`, `messaging/account/{get,list,update,remove,add}`, `messaging/acl/get`,
`messaging/access-list/{update,list}`, `audit/list`, `config/{show,patch,reload}`, `messaging/stats/show`, `messaging/queue/{list,status,purge}`,
`messaging/message/{list,get,delete,status}`, `messaging/monitor/{subscribe,unsubscribe}`. 0.2 also served for audit/list, account/{add,get,list,update}, message/status
(trust-tasks.toml; trust_tasks.rs:243-251 maps 0.2 to the 0.1 handler). Retired and refused (`protocol.trust_task.unsupported`, 501, trust_tasks.rs:218-224):
`admin/add`, `admin/strip`, `admin/list`, `acl/set`, `change-type`, `access-list/{add,remove,clear,get}`. So:
- account add = `messaging/account/add/0.1`; get/update/remove likewise; admin list = `messaging/account/list/0.1` with `accountType` filter (trust_tasks.rs:~686-740);
- acl get = `messaging/acl/get/0.1`; acl set = `messaging/account/update/0.1` with `acl` member (trust_tasks.rs:811-910);
- access-list update/list = `messaging/access-list/{update,list}/0.1`.

Document (what `consume` needs): top-level members `id, type, issuer?, recipient, issuedAt, payload, proof?` (kit's `task()` in mediator-acl.mjs:~190-200 is
the working shape). `recipient` must equal the mediator DID (`validate_basic`, e.g. trust_tasks.rs:622). Policy from bundles:
- account/add, access-list/update: `proofRequired`, `issuedAtRequired`, `recipientRequired` all true (request).
- account/get, access-list/list: only `recipientRequired`.
Proof = Data Integrity `eddsa-jcs-2022`/`eddsa-rdfc-2022`, verified over the raw document; key must be in issuer's `authentication` or `assertionMethod`
(trust_task_verify.rs:~327-338, 133-152, 253-259 doc). `issuer`, if present, must `same_account` as the authenticated sender (trust_task_verify.rs:~205-211).
Enforcement is `security.trust_task_verification` = `warn` (DEFAULT) or `enforce` (security.rs:323-329, default Warn at :450); the kit forces `enforce`.
Replay: consequential tasks (proof/issuedAt required) claim `(sender, id)`; reuse -> `message.trust_task.duplicate` (trust_task_verify.rs:~272-310).
`payload.did` is used AS the account key, i.e. the SHA-256 hex of the DID, not the DID itself (`target_hash = typed.payload.did`, trust_tasks.rs:633, 1451, 1544;
`did_hash = sha256(account_did(did))`, mediator-common did_identity.rs:23-25). Matches the kit's `sha256hex()`.

Example DIDComm plaintext (before authcrypt), account add (built from the cited sources, not copied from a test; the repo has no DIDComm admin example):
```json
{ "id":"urn:uuid:...", "typ":"application/didcomm-plain+json",
  "type":"https://trusttasks.org/binding/didcomm/0.1/envelope",
  "from":"<ADMIN_DID>", "to":["<MEDIATOR_DID>"], "created_time":1700000000, "expires_time":1700000300,
  "body": { "id":"urn:uuid:...", "type":"https://trusttasks.org/spec/messaging/account/add/0.1",
            "issuer":"<ADMIN_DID>", "recipient":"<MEDIATOR_DID>", "issuedAt":"2026-11-16T00:00:00Z",
            "payload": { "did":"<sha256hex(new DID)>", "accountType":"standard",
                         "acl": { "accessListMode":"explicitDeny","selfManageList":true,"local":true,"sendMessages":true,"receiveMessages":true } },
            "proof": { "type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","verificationMethod":"<ADMIN_DID>#<authn key>","proofPurpose":"assertionMethod","created":"...","proofValue":"z..." } } }
```
access-list/update payload (schema: bundles/messaging/access-list/update/0.1): `{ "did":"<hash of target>", "clear":false, "add":["<hash>"], "remove":["<hash>"] }`
(`did` required; `clear` empties before `add`, trust_tasks.rs:1451-1466). access-list/list payload: `{ "did":"<hash>", "entries":["<hash>"], "cursor":"..", "limit":N }`
(`did` required; `entries` = membership filter; list proof/issuedAt not required). Response docs: `...#response` type, signed by the mediator (trust_task_sign.rs).

## 3. `check_admin_signature` and `block_remote_admin_msgs`

`check_admin_signature(session, sender_kid)` (M/src/common/authz.rs:189-196):
```rust
match sender_kid { Some(kid) => kid.split_once('#').is_some_and(|(did,_)| same_account(did, &session.did)), None => false }
```
- It checks ONLY that the sender key id has a `#fragment` and that its DID part equals the SESSION DID (did:scid `?src=` tolerated). It does not
  check which key, nor that a signature exists, nor the relationship (authentication/assertion/keyAgreement).
- `sender_kid` is filled by the DIDComm path as `metadata.sign_from.or(metadata.encrypted_from_kid)` (trust_tasks.rs:~109-120). So a JWS signer kid
  (`did#authn-key`) OR the authcrypt `skid` (`did#keyAgreement-key`) both satisfy it. An authcrypt message from the admin DID alone passes.
  If BOTH exist they must name the same DID (messages/mod.rs:67-80, else sender-mismatch problem).
- `check_permissions` (authz.rs:206-226): the signature test applies only `if check_admin_signing && session is Admin/RootAdmin` (:213-217); then
  Admin/RootAdmin may act on any DID, anyone else only on own hash (:219-225). `check_admin_signing` is passed as `config.security.block_remote_admin_msgs`
  (default `true`, security.rs:449; call sites trust_tasks.rs:634-638, 894-898, 1074-1078, 1264-1268, 1306-1311; mediator_ops.rs:223-228, 399-404).
  Meaning: with `block_remote_admin_msgs = true` an admin session acting through these handlers must present a sender kid whose DID is the session DID, i.e. admin
  messages cannot be relayed on the admin's behalf by another DID. With `false` the test is skipped (validate.rs:212-218 warns about it).
- Which tasks call `check_permissions`: account/get, account/update (only when `acl`/`queueLimits` present, :889-899), account/remove, acl/get, access-list/{update,list}
  (`authorize_access_list`, :1299-1331), queue status, message list/get/delete/purge. Tasks that DO NOT: account/add (:1137 - `is_admin` from session type; in explicit_allow mode non-admin refused :1171-1173),
  account/list, audit/list, config/*, stats/show use `require_admin`/session type only (trust_tasks.rs:1618-1633).
- Finding (source-derived, check against a live run): over TSP `sender_kid` is the bare VID with no `#` (trust_tasks.rs:~463 / inbound.rs dispatch_tsp_trust_task passes `sender_vid`;
  comment "TSP VIDs carry no key fragment"). `split_once('#')` is then `None` -> `check_admin_signature` = false -> an ADMIN session going through `check_permissions` with
  `block_remote_admin_msgs=true` is refused (`authorization.account.denied`), even for access-list/update on its own hash. Non-admin self-service passes (the signature branch is skipped for non-admins).
  This is the reason admin calls like access-list/update, acl, account/get|remove|update-acl work over DIDComm (kid has `#`) but, by this reading, not over TSP. account/add and account/list do not hit it.
- The JWS (if you add one) must carry `kid` in the PROTECTED header, `alg` EdDSA/Ed25519/ES256/ES256K, and verify against the DID's `authentication` relationship
  (didcomm_compat.rs:~285-330 kid provenance, :543-587 `verify_inner_jws`, :694-709 `resolve_authentication_vm`: prefers the exact kid if listed in `authentication`, else the first
  authentication key). `assertionMethod` is not consulted for the JWS. A JWS is optional for admin ops; recognised only as sign-then-encrypt INSIDE a JWE (didcomm_compat.rs:~265-300).
  A bare outer JWS is accepted by `unpack_jws` but then `to_did` is None, so it would not route to the mediator (inbound.rs:1181+ "no to_did").
  Layering accepted: authcrypt(plaintext), authcrypt(sign(plaintext)), anoncrypt(sign(...)), anoncrypt(authcrypt(...)) (didcomm_compat.rs:327-353 doc; unusual stacks only warn).
  Note anoncrypt(sign()) is "authenticated" only through `sign_from`, which is enough for `block_anonymous_outer_envelope` (inbound.rs:1105-1108) and for sender_kid.

## 4. Can `@openvtc/vti-didcomm-js` 0.13.0 build the envelope?

Installed at `sandbox/tsp-tests/node_modules/@openvtc/vti-didcomm-js` (npm ci worked). README "Not implemented": "signed-only (JWS) mode"
(README.md:~47-50); `grep -i "jws|signatures" src` finds nothing but comments. **No JWS signing function exists.** So `sign(plaintext)` is NOT producible by the library; you'd have to
write a small Ed25519 JWS (General JSON: `{payload, signatures:[{protected:b64u({"typ":"application/didcomm-signed+json","alg":"EdDSA","kid":"<did>#<authn>"}), signature}]}`) yourself with `@noble/curves` ed25519, then feed its string as
the plaintext of the library's authcrypt (but `pack` takes `message` as an object and JSON-serialises it, so wrapping an arbitrary JWS string likely needs `pack` changed / reimplemented: check `src/pack.js`). That is only needed if you want `sign_from`;
authcrypt alone already satisfies check_admin_signature (section 3), so the JWS is optional.
Available (types/index.d.ts): 
- `pack({message, sender:{kid, privateJwk}, recipient:{kid, publicJwk}}): Promise<string>` — authcrypt JWE (ECDH-1PU+A256KW, A256CBC-HS512), X25519 or P-256 (types/pack.d.ts).
- `packAnoncrypt({message, recipient:{kid, publicJwk}}): Promise<string>` (types/anoncrypt.d.ts).
- `unpack(jwe, {kid, privateJwk}, {publicJwk}?)` returns `{message, senderDid, senderKid, authenticated}`; throws `SenderMismatchError` if `from` != skid DID.
- `buildForward({next, from, mediatorDid, innerJwe})` -> routing/2.0 forward plaintext (types/forward.d.ts). Not needed for admin (message is addressed straight to the mediator).
- `authenticateToMediator({mediatorDid, clientDid, clientX25519Private, clientX25519Public, clientKid?, fetch?, netPolicy?, allowInsecure?, resolve?})` ->
  `{accessToken, accessExpiresAt, refreshToken, refreshExpiresAt, sessionId, mediator:{did, restEndpoint, wsEndpoint, authEndpoint, kid, x25519Pub}}` (types/mediator-auth.d.ts; src/mediator-auth.js:85-175).
  It does exactly section 1: POST `${authEndpoint}/challenge`, then POST `authEndpoint` with authcrypt JWE of `{id, typ, type:".../atm/1.0/authenticate", from, to:[mediatorDid], created_time, expires_time:+300, body:{challenge,session_id}}`
  (mediator-auth.js:125-159). Default `clientKid = ${did}#${multikey(X25519 pub)}` (:343-346). Endpoints come from the mediator DID doc (`resolveMediator`); egress policy is https-only + public hosts, so local `http://127.0.0.1` needs
  `netPolicy:{allowInsecure:true, allowPrivate:true}`; but the auth fetch is created with `schemes:["https:"]` (mediator-auth.js:~120) — check whether it still accepts http for a local test (not verified).
- `resolve(did)` (did:key, did:peer numalgo 2, did:webvh, did:scid), `didKey.ed25519PublicKeyToX25519(edPub)` (did-key.js:210), `jwk.privateJwk/publicJwk`, `MediatorSession` (WebSocket only; `send(jweString)` for WS text frames, `waitFor(thid, ms, {from})`,
  `TRUST_TASK_ENVELOPE_TYPE`, `isStoredMediatorReply`). `MediatorSession.send` goes over `/ws`; there is NO REST `/inbound` or `/fetch` helper (grep "inbound" finds comments only), so use plain `fetch` with the Bearer token for those.
- did:peer:2 resolution is in-tree (`resolve`/`didPeer`), numalgo 2 only. The recipient key to authcrypt to is the mediator's X25519 keyAgreement kid (`resolveMediator().kid`, `.x25519Pub`); it MUST be a kid whose DID part is the mediator DID (inbound.rs:1071).
Gap summary: (a) no JWS signer (optional, see above); (b) no helper to POST a packed admin JWE to `/inbound` and read the reply via `/fetch` (trivial `fetch`; reply is an authcrypt JWE from the mediator DID, decrypt with `unpack`);
(c) no Trust Task / Data-Integrity proof helper — reuse the kit's `attachProof()` (lib.mjs:49-53) for `proof`; (d) a did:key admin works with `pack`: skid = `did:key:z6Mk...#z6LS...` (X25519 from `ed25519PublicKeyToX25519`), and the admin DID in the kit
(`ADMIN` in mediator-acl.mjs) is a did:key whose `X25519` secret is `ed25519.utils.toMontgomerySecret(sk)`, already computed as `ADMIN.dk/.epk`.

## 5. What a NON-admin signed-in DID can make the mediator act on (DIDComm, `to` = mediator DID)

Gate before any handler: session ACL `SEND_MESSAGES` (message_inbound.rs:78); `force_session_did_match` (inbound.rs:1131). Dispatch table = `MessageType::process`, messages/mod.rs:155-256:
| type (enum) | handler | line | non-admin outcome |
|---|---|---|---|
| `https://didcomm.org/trust-ping/2.0/ping` | `ping::process` | mod.rs:163, ping.rs:30 | works (pong if response_requested) |
| `https://trusttasks.org/binding/didcomm/0.1/envelope` | `trust_tasks::process` | mod.rs:164, trust_tasks.rs:99 | any of the 23 served tasks; self-or-admin ones succeed on own hash only (`check_permissions` authz.rs:219-225); admin-only (`account/list`, `audit/list`, `config/*`, `stats/show`, ...) refused `authorization.admin_required`; `account/add` allowed to non-admin ONLY in explicit_deny mode (trust_tasks.rs:1171) |
| `https://didcomm.org/messagepickup/3.0/status-request` | `message_pickup::status_request` | mod.rs:167, pickup.rs:36 | works (own inbox) |
| `.../delivery-request` | `delivery_request` | mod.rs:181, :308 | works |
| `.../messages-received` | `messages_received` | mod.rs:184, :409 | works |
| `.../live-delivery-change` | `toggle_live_delivery` | mod.rs:187, :192 | works (WS) |
| `.../messagepickup/3.0/status` (response) | - | mod.rs:170 | refused, 501 |
| `https://didcomm.org/routing/2.0/forward` | `routing::process` | mod.rs:212, routing.rs:825 | needs `SEND_FORWARDED` on the authenticated sender (resolve_forward_sender, routing.rs:703-808, 790/805) and the next hop's `RECEIVE_FORWARDED` (:556); next hop local or remote (`remote_endpoint_for`). "Forwarding off" settings in the kit (`external_forwarding=false`, `enable_inter_mediator_relay=false`) only close the REMOTE leg; a local forward still stores into a local account if ACLs allow. The kit's `global_acl_default` has no `SEND_FORWARDED`, so a new account is refused (403). Seed ACL for an unseen forward sender is `relay_sender_acls` (routing.rs:~45-60) |
| `https://didcomm.org/discover-features/2.0/queries` | `discover_features::process` | mod.rs:226, df.rs:13 | works; needs `from` |
| `.../discover-features/2.0/disclose`, `.../report-problem/2.0/problem-report` | - | mod.rs:229, 215 | refused 501 |
| `https://affinidi.com/atm/1.0/authenticate`, `.../authenticate/refresh` | - | mod.rs:190, 201 | refused 400 "must use the /authenticate endpoint" |
| anything else (`SDKMessageType::Other`) | - | mod.rs:240 | refused 501 `me.not_implemented` |
Not present: coordinate-mediation / keylist for DIDComm v2 (discover_features.rs:~119-150 `ADVERTISED_PROTOCOLS`: discover-features, routing, trust-ping, out-of-band, messagepickup/3.0, atm authenticate, report-problem;
a test pins that coordinate-mediation is absent). DIDComm v1 keylist exists only for v1 envelopes (messages/v1_mediation.rs, inbound_v1.rs). Out-of-band: REST `/oob` routes (mod.rs:96-98), not a message type.
Other non-handler paths on `/inbound`: direct delivery to a local account when `to` is not the mediator (inbound.rs:1176+, gated `local_direct_delivery_allowed`, sender `SEND_MESSAGES`, recipient `RECEIVE_MESSAGES` + access list);
`RelayMode::Rewrap` peel (inbound.rs:1035-1041, only when configured). Pickup/WS of the DID's own inbox via `/fetch` and `/ws`.

## 6. Sign-in JSON/REST shapes (exact)
- `POST /mediator/v1/authenticate/challenge`  `Content-Type: application/json`  `{"did":"<did>"}` ->
  200 `{"session_id":"<12>","http_code":200,"error_code":0,"error_code_str":"NA","message":"Success","data":{"challenge":"<32>","session_id":"<12>"}}` (challenge.rs:139-148; SuccessResponse is snake_case as in `SuccessResponse` literal fields, message_inbound.rs:285-298).
- `POST /mediator/v1/authenticate`  body = JWE JSON `{protected, recipients:[{header:{kid}, encrypted_key}], iv, ciphertext, tag}` (authcrypt, plaintext = auth message in section 1) ->
  `{"session_id":"<new 12>","http_code":200,...,"data":{"access_token":"..","access_expires_at":<unix>,"refresh_token":"..","refresh_expires_at":<unix>}}` (response.rs:363-425).
- Errors are `ProblemReport` bodies: `authentication.blocked` 403, `authentication.response.parse` 400, `authentication.message.not_signed_or_encrypted` 400, `message.expires_time.missing` 400, `authentication.session.mismatch` 400, `authentication.session.invalid` 400.
- Then `POST /mediator/v1/inbound` with `Authorization: Bearer <access_token>`, body = admin JWE; `POST /mediator/v1/fetch` `{"limit":20,"delete_policy":"Optimistic"}` (same call the kit uses) to read the stored reply; the reply JWE is authcrypt from the mediator DID to the admin's keyAgreement key.

## Practical recipe for the kit (from the above)
1. Sign in with `authenticateToMediator` (admin did:key or did:peer; X25519 from Ed25519 via `ed25519PublicKeyToX25519`).
2. Build the Trust Task doc exactly as in `task()` (mediator-acl.mjs:~190-200) incl. `recipient`, `issuedAt`, `attachProof` (needed under enforce for account/add, access-list/update).
3. Plaintext DIDComm = envelope type + `body: doc`, `from` = admin DID, `to:[mediator DID]`, `expires_time` set (mod.rs:342-370 rejects expired).
4. `pack` (authcrypt, sender skid = `<admin did>#<x25519 kid>`, recipient kid = mediator keyAgreement kid) -> POST `/inbound` with Bearer. No separate JWS is required for `check_admin_signature`.
5. Read the answer via `/fetch` and `unpack` it; correlate by `thid` = request message id (trust_tasks.rs:166-171).
Caveat: unverified against a running mediator; confirm in a live run that the `sign_from`-less authcrypt path passes `check_admin_signature` as read.
