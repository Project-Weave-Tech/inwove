//! Test harness CLI around didwebvh-rs 0.8.2. Test keys only: every key is generated in the process and dropped with it.
//!
//! Subcommands (all print one JSON object on stdout; exit code 0 = the command ran, the JSON says whether the log verified):
//!   create-log   <dir> <host>                     four-step log (prerotation, rotate, witness 2-of-2, witness 1-of-1)
//!   resolve-file <did> <log> [witness] [--version N]   local files only, no network
//!   resolve-http <did> <map-host=127.0.0.1> [--version N]   fetch from the DID's host over HTTP (host mapped locally)
use chrono::{Duration, Utc};
use didwebvh_rs::log_entry::{LogEntry, LogEntryMethods, MetaData};
use didwebvh_rs::prelude::*;
use didwebvh_rs::resolve::ResolveOptions;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::sync::Arc;

type R<T> = Result<T, Box<dyn std::error::Error>>;

/// didwebvh pre-rotation hash: base58btc( 0x12 0x20 || sha256(multikey as utf-8) ).
fn next_key_hash(multikey: &str) -> String {
    use base58::ToBase58;
    let digest = Sha256::digest(multikey.as_bytes());
    let mut mh = vec![0x12u8, 0x20];
    mh.extend_from_slice(&digest);
    mh.to_base58()
}

fn pk(s: &Secret) -> String {
    s.get_public_keymultibase().expect("public key")
}

fn doc(vm_key: &str, with_service: bool) -> Value {
    let mut d = json!({
        "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"],
        "id": "{DID}",
        "verificationMethod": [{
            "id": "{DID}#key-0", "type": "Multikey", "controller": "{DID}", "publicKeyMultibase": vm_key
        }],
        "authentication": ["{DID}#key-0"],
        "assertionMethod": ["{DID}#key-0"],
    });
    if with_service {
        d["service"] = json!([{ "id": "{DID}#site", "type": "LinkedDomains", "serviceEndpoint": "https://example.test/" }]);
    }
    d
}

fn witnesses(ids: &[&Secret], threshold: u32) -> R<Witnesses> {
    let mut b = Witnesses::builder().threshold(threshold);
    for s in ids {
        b = b.witness(Multibase::new(pk(s)));
    }
    Ok(b.build()?)
}

async fn create_log(dir: &str, host: &str) -> R<Value> {
    let base = Utc::now().fixed_offset() - Duration::seconds(600);
    let at = |n: i64| base + Duration::seconds(n * 60);
    let (_, k0) = generate_did_key(KeyType::Ed25519)?;
    let (_, k1) = generate_did_key(KeyType::Ed25519)?;
    let (_, dk) = generate_did_key(KeyType::Ed25519)?;
    let (_, w1) = generate_did_key(KeyType::Ed25519)?;
    let (_, w2) = generate_did_key(KeyType::Ed25519)?;
    let mut notes: Vec<String> = vec![];

    // 1. create, pre-rotation: nextKeyHashes commits to k1; portable so a move is possible later
    let params = Parameters {
        update_keys: Some(Arc::new(vec![Multibase::new(pk(&k0))])),
        next_key_hashes: Some(Arc::new(vec![Multibase::new(next_key_hash(&pk(&k1)))])),
        portable: Some(true),
        ..Default::default()
    };
    let created = create_did(
        CreateDIDConfig::builder()
            .address(format!("https://{host}/"))
            .authorization_key(k0.clone())
            .did_document(doc(&pk(&dk), false))
            .parameters(params)
            .version_time(at(0))
            .build()?,
    )
    .await?;
    let did = created.did().to_string();
    let mut state = DIDWebVHState::from_log_entries(vec![created.log_entry().clone()]);
    state.validate()?.assert_complete()?;
    notes.push("v1 created".into());

    // 2. rotate once, consuming the pre-committed k1 (signed by k1); prerotation ends (nextKeyHashes = [])
    let mut d2 = doc(&pk(&dk), true);
    replace_did(&mut d2, &did);
    let r = update_did(
        UpdateDIDConfig::builder()
            .state(state)
            .signing_key(k1.clone())
            .document(d2.clone())
            .update_keys(vec![Multibase::new(pk(&k1))])
            .next_key_hashes(vec![])
            .version_time(at(1))
            .build()?,
    )
    .await?;
    let mut state = r.into_state();
    notes.push("v2 rotated".into());

    // 3. witness rule 2-of-2
    let r = update_did(
        UpdateDIDConfig::builder()
            .state(state)
            .signing_key(k1.clone())
            .witness(witnesses(&[&w1, &w2], 2)?)
            .witness_secret(format!("did:key:{}", pk(&w1)), w1.clone())
            .witness_secret(format!("did:key:{}", pk(&w2)), w2.clone())
            .version_time(at(2))
            .build()?,
    )
    .await?;
    state = r.into_state();
    notes.push(format!("v3 witness 2-of-2; proofs after v3: {}", state.witness_proofs().get_total_count()));

    // 4. change to 1-of-1 (w1)
    let r = update_did(
        UpdateDIDConfig::builder()
            .state(state)
            .signing_key(k1.clone())
            .witness(witnesses(&[&w1], 1)?)
            .witness_secret(format!("did:key:{}", pk(&w1)), w1.clone())
            .witness_secret(format!("did:key:{}", pk(&w2)), w2.clone())
            .version_time(at(3))
            .build()?,
    )
    .await?;
    state = r.into_state();
    notes.push(format!("v4 witness 1-of-1; proofs after v4: {}", state.witness_proofs().get_total_count()));

    std::fs::create_dir_all(dir)?;
    let log: String = state
        .log_entries()
        .iter()
        .map(|e| serde_json::to_string(&e.log_entry).map(|s| s + "\n"))
        .collect::<Result<_, _>>()?;
    std::fs::write(format!("{dir}/did.jsonl"), log)?;
    state.witness_proofs().save_to_file(&format!("{dir}/did-witness.json"))?;
    Ok(json!({ "ok": true, "did": did, "entries": state.log_entries().len(), "notes": notes }))
}

fn replace_did(v: &mut Value, did: &str) {
    match v {
        Value::String(s) => *s = s.replace("{DID}", did),
        Value::Array(a) => a.iter_mut().for_each(|x| replace_did(x, did)),
        Value::Object(o) => o.values_mut().for_each(|x| replace_did(x, did)),
        _ => {}
    }
}

fn with_version(did: &str, version: Option<&str>) -> String {
    match version {
        Some(n) => format!("{did}?versionNumber={n}"),
        None => did.to_string(),
    }
}

fn answer(r: Result<(LogEntry, MetaData), DIDWebVHError>) -> Value {
    match r {
        Ok((entry, meta)) => match entry.get_did_document() {
            Ok(d) => json!({
                "ok": true,
                "scid": meta.scid, "versionId": meta.version_id, "versionNumber": meta.version_number,
                "portable": meta.portable, "deactivated": meta.deactivated,
                "witness": serde_json::to_value(&meta.witness).unwrap_or(Value::Null),
                "document": d, "id": d.get("id"),
            }),
            Err(e) => json!({ "ok": false, "error": format!("{e}") }),
        },
        Err(e) => json!({ "ok": false, "error": format!("{e}") }),
    }
}

fn flag(args: &mut Vec<String>, name: &str) -> Option<String> {
    let i = args.iter().position(|a| a == name)?;
    args.remove(i);
    Some(args.remove(i))
}

#[tokio::main]
async fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let version = flag(&mut args, "--version");
    let out = run(args, version).await;
    match out {
        Ok(v) => println!("{v}"),
        Err(e) => println!("{}", json!({ "ok": false, "error": format!("{e}") })),
    }
}

async fn run(args: Vec<String>, version: Option<String>) -> R<Value> {
    let a: Vec<&str> = args.iter().map(String::as_str).collect();
    match a.as_slice() {
        ["version"] => Ok(json!({ "ok": true, "tool": "wpi-webvh-rs", "didwebvh-rs": "0.8.2" })),
        ["create-log", dir, host] => create_log(dir, host).await,
        ["resolve-file", did, log, rest @ ..] => {
            let raw = std::fs::read_to_string(log)?;
            let wit = rest.first().and_then(|p| std::fs::read_to_string(p).ok());
            let mut st = DIDWebVHState::default();
            Ok(answer(st.resolve_log_owned(&with_version(did, version.as_deref()), &raw, wit.as_deref()).await))
        }
        // probe <did>...: the library's NORMAL network path (default options: public hosts only), one json line per DID.
        ["probe", dids @ ..] => {
            for did in dids {
                let mut st = DIDWebVHState::default();
                let r = answer(st.resolve_owned(did, ResolveOptions::default()).await);
                println!("{}", json!({ "did": did, "ok": r["ok"], "error": r["error"] }));
            }
            Ok(json!({ "ok": true, "probed": dids.len() }))
        }
        // resolve-http <did> <hostname=ip> ...: fetch over HTTP, the DID's hostnames pinned to local addresses.
        ["resolve-http", did, maps @ ..] => {
            let mut cb = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).no_proxy();
            for m in maps {
                let (h, ip) = m.split_once('=').ok_or("map is host=ip")?;
                cb = cb.resolve(h, SocketAddr::new(ip.parse()?, 0));
            }
            let opts = ResolveOptions {
                host_policy: HostPolicy::AllowPrivate,
                http_client: Some(cb.build()?),
                timeout: Some(std::time::Duration::from_secs(10)),
                ..ResolveOptions::default()
            };
            let mut st = DIDWebVHState::default();
            Ok(answer(st.resolve_owned(&with_version(did, version.as_deref()), opts).await))
        }
        _ => Err("usage: create-log <dir> <host> | resolve-file <did> <log> [witness] [--version N] | resolve-http <did> host=ip... [--version N]".into()),
    }
}

