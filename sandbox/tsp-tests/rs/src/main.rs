// ref/09 Rust peer: affinidi-tsp 0.3.0 driven by JSON lines on stdin, one reply line per command on stdout.
// Test keys only: every key comes from the test harness and dies with the process.
use affinidi_tsp::{PrivateVid, ResolvedVid, TspAgent, message::direct};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use serde_json::{Value, json};
use std::io::{BufRead, Write};

fn k32(v: &Value, f: &str) -> Result<[u8; 32], String> {
    let h = v[f].as_str().ok_or(format!("missing {f}"))?;
    let b = hex::decode(h).map_err(|e| e.to_string())?;
    b.try_into().map_err(|_| format!("{f} must be 32 bytes"))
}
fn s<'a>(v: &'a Value, f: &str) -> Result<&'a str, String> { v[f].as_str().ok_or(format!("missing {f}")) }
fn bytes(v: &Value, f: &str) -> Result<Vec<u8>, String> { B64.decode(s(v, f)?).map_err(|e| e.to_string()) }

fn run(agent: &TspAgent, c: &Value) -> Result<Value, String> {
    let e = |x: affinidi_tsp::TspError| format!("{x}");
    match s(c, "op")? {
        "private" => {
            agent.add_private_vid(PrivateVid::from_keys(s(c, "id")?, k32(c, "sk")?, k32(c, "dk")?));
            Ok(json!({}))
        }
        "remote" => {
            agent.add_verified_vid(ResolvedVid { id: s(c, "id")?.into(), signing_key: k32(c, "spk")?, encryption_key: k32(c, "epk")?, endpoints: vec![], mediators: vec![] });
            Ok(json!({}))
        }
        // Low level: no relationship, no store. The keys travel in the command.
        "pack" => {
            let p = direct::pack(&bytes(c, "payload")?, affinidi_tsp::MessageType::Direct, s(c, "from")?, s(c, "to")?, &k32(c, "sk")?, &k32(c, "epk")?).map_err(e)?;
            Ok(json!({"bytes": B64.encode(&p.bytes)}))
        }
        "unpack" => {
            let u = direct::unpack(&bytes(c, "bytes")?, &k32(c, "dk")?, &k32(c, "spk")?).map_err(e)?;
            Ok(json!({"payload": B64.encode(&u.payload), "sender": u.sender, "receiver": u.receiver, "type": format!("{:?}", u.message_type)}))
        }
        // High level: the agent keeps relationship state for the life of the process.
        "invite" => { let p = agent.send_relationship_invite(s(c, "from")?, s(c, "to")?).map_err(e)?; Ok(json!({"bytes": B64.encode(&p.bytes), "digest": hex::encode(p.thread_digest)})) }
        "accept" => { let p = agent.send_relationship_accept(s(c, "from")?, s(c, "to")?).map_err(e)?; Ok(json!({"bytes": B64.encode(&p.bytes), "digest": hex::encode(p.thread_digest)})) }
        "send" => { let p = agent.send(s(c, "from")?, s(c, "to")?, &bytes(c, "payload")?).map_err(e)?; Ok(json!({"bytes": B64.encode(&p.bytes)})) }
        "receive" => {
            let r = agent.receive(s(c, "our")?, &bytes(c, "bytes")?).map_err(e)?;
            Ok(json!({"payload": B64.encode(&r.payload), "sender": r.sender, "type": format!("{:?}", r.message_type),
                      "digest": hex::encode(r.thread_digest), "control": r.control.map(|x| format!("{x:?}")), "outcome": format!("{:?}", r.outcome)}))
        }
        "state" => Ok(json!({"state": format!("{:?}", agent.relationship_state(s(c, "our")?, s(c, "their")?))})),
        o => Err(format!("unknown op {o}")),
    }
}

fn main() {
    let agent = TspAgent::new();
    let stdin = std::io::stdin();
    let mut out = std::io::stdout().lock();
    for line in stdin.lock().lines() {
        let line = match line { Ok(l) => l, Err(_) => break };
        if line.trim().is_empty() { continue; }
        let reply = match serde_json::from_str::<Value>(&line) {
            Ok(c) => match run(&agent, &c) { Ok(v) => json!({"ok": true, "r": v}), Err(m) => json!({"ok": false, "error": m}) },
            Err(m) => json!({"ok": false, "error": format!("bad json: {m}")}),
        };
        writeln!(out, "{reply}").unwrap();
        out.flush().unwrap();
    }
}
