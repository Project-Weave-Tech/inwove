#!/usr/bin/env python3
"""didwebvh-py (installed from the pinned git sha) as a command line. Prints ONE json object on stdout.

  py_resolve.py resolve-file <did> <log> [witness-file-ignored] [--version N]
      Local files only: resolves from <log>; the witness file is read from beside the log (did-witness.json) by the library.
  py_resolve.py probe <did> [<did> ...]
      The library's NORMAL (network) path for each DID, one json line per DID. Run only under `unshare -n` + strace:
      the netwatch job passes if it refuses without connecting.

UNTESTED against the pinned sha on the machine this was written on (github.com was unreachable there); the API below was
read from the PyPI release did-webvh 1.0.1 (did_webvh.resolver.resolve_did). If the pinned sha moved the API, this prints
the names it found, so the first CI run says what to change.
"""
import asyncio
import json
import sys
from pathlib import Path


def out(obj):
    print(json.dumps(obj, sort_keys=True))


def load_api():
    try:
        from did_webvh.resolver import resolve_did  # noqa: PLC0415
        return resolve_did, None
    except Exception as e:  # noqa: BLE001
        names = []
        try:
            import did_webvh  # noqa: PLC0415
            names = sorted(n for n in dir(did_webvh) if not n.startswith("_"))
        except Exception:  # noqa: BLE001
            pass
        return None, f"cannot import did_webvh.resolver.resolve_did: {e!r}; did_webvh exports: {names}"


def result_to_json(res):
    doc = getattr(res, "document", None)
    meta = getattr(res, "document_metadata", None) or {}
    rmeta = getattr(res, "resolution_metadata", None) or {}
    if not doc:
        return {"ok": False, "error": f"no document: {json.dumps(rmeta, sort_keys=True)[:300]}"}
    vid = meta.get("versionId")
    return {
        "ok": True,
        "scid": meta.get("scid"),
        "versionId": vid,
        "versionNumber": int(str(vid).split("-")[0]) if vid else None,
        "document": doc,
        "id": doc.get("id"),
    }


async def resolve_file(did, log, version):
    resolve_did, err = load_api()
    if err:
        return {"ok": False, "error": err}
    try:
        kw = {"local_history": Path(log)}
        if version:
            kw["version_number"] = int(version)
        res = await resolve_did(did, **kw)
        r = result_to_json(res)
        if r["ok"] and r["id"] != did:
            return {"ok": False, "error": f"document id {r['id']} is not the asked DID {did}"}
        return r
    except BaseException as e:  # noqa: BLE001 - any error is a refusal
        return {"ok": False, "error": f"threw: {type(e).__name__}: {e}"[:300]}


async def probe(dids):
    resolve_did, err = load_api()
    for did in dids:
        if err:
            out({"did": did, "ok": False, "error": err})
            continue
        try:
            res = await asyncio.wait_for(resolve_did(did), timeout=20)
            r = result_to_json(res)
            out({"did": did, "ok": r["ok"], "error": r.get("error")})
        except BaseException as e:  # noqa: BLE001
            out({"did": did, "ok": False, "error": f"{type(e).__name__}: {e}"[:300]})


def main():
    args = sys.argv[1:]
    version = None
    if "--version" in args:
        i = args.index("--version")
        version = args[i + 1]
        del args[i : i + 2]
    if not args:
        out({"ok": False, "error": "usage: resolve-file | probe"})
        return
    cmd, rest = args[0], args[1:]
    if cmd == "resolve-file":
        did, log = rest[0], rest[1]
        out(asyncio.run(resolve_file(did, log, version)))
    elif cmd == "probe":
        asyncio.run(probe(rest))
    else:
        out({"ok": False, "error": "usage: resolve-file | probe"})


if __name__ == "__main__":
    main()
