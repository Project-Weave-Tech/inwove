#!/usr/bin/env node
// The base image's registry chain, fetched by digest (Security 12197.2, Railroad 12183.1, Security 12232.1). The rekey
// config record's base half used to be tied only to `docker image inspect`, whose `.Id` on this runner's containerd
// store is the INDEX digest, not a config digest. So this reads the three blobs the pin actually names, raw, from the
// registry, and the verdict (mediator-image-config.mjs, chainVerdict) checks every hash itself:
//   index.raw     the image index, fetched by the digest pinned on the rekey Dockerfile's FROM line
//   manifest.raw  the one linux/amd64 manifest (no variant) the index lists, fetched by its descriptor's digest
//   config.raw    that manifest's config blob, fetched by its config.digest
//   layers/<i>.blob  each layer the manifest names, in order, fetched by its digest (Security 12327.1); judged, and
//                 applied, by mediator-base-layers.mjs
// This script only fetches and writes bytes; it judges nothing, so a registry (or a proxy) that answers with other
// bytes is caught by the verdict, not trusted here. Anonymous pull token only; the token is never printed or written.
// A failed fetch writes what it got and exits 1; the verdict then reads the missing file as red, never as a pass.
//
//   mediator-base-fetch.mjs <name[:tag]@sha256:<index digest>> <out dir> [--no-layers]
// (--no-layers: the chain only, for a base whose layers are judged from the image's own save, Security 12430 (d))
import fs from 'node:fs';
import path from 'node:path';

const INDEX_TYPES = ['application/vnd.oci.image.index.v1+json', 'application/vnd.docker.distribution.manifest.list.v2+json'];
const MANIFEST_TYPES = ['application/vnd.oci.image.manifest.v1+json', 'application/vnd.docker.distribution.manifest.v2+json'];

// "node:22-bookworm-slim@sha256:…" → {repo: "library/node", digest}. Docker Hub only (the one base we pin).
export function parseRef(ref) {
  const m = /^(?:docker\.io\/)?([a-z0-9][a-z0-9._/-]*?)(?::[A-Za-z0-9._-]+)?@(sha256:[0-9a-f]{64})$/.exec(String(ref));
  if (!m) return null;
  return { repo: m[1].includes('/') ? m[1] : `library/${m[1]}`, digest: m[2] };
}

// The one linux/amd64 manifest descriptor with no variant, or null when there is none or more than one.
export function amd64Descriptor(index) {
  const hits = (index?.manifests || []).filter((d) => d?.platform?.os === 'linux' && d?.platform?.architecture === 'amd64' && !d?.platform?.variant);
  return hits.length === 1 ? hits[0] : null;
}

async function main([ref, out, flag]) {
  if (!out) { console.error('usage: mediator-base-fetch.mjs <name[:tag]@sha256:…> <out dir>'); return 2; }
  const r = parseRef(ref);
  if (!r) { console.error('mediator-base-fetch: the base is not a Docker Hub name pinned by digest'); return 1; }
  fs.mkdirSync(out, { recursive: true });
  const tok = await fetch(`https://auth.docker.io/token?service=registry.docker.io&scope=repository:${r.repo}:pull`);
  if (!tok.ok) { console.error(`mediator-base-fetch: token HTTP ${tok.status}`); return 1; }
  const { token } = await tok.json();
  const H = (accept) => ({ Authorization: `Bearer ${token}`, ...(accept ? { Accept: accept.join(', ') } : {}) });
  const get = async (kind, digest, accept) => {
    // Blobs redirect to a CDN; fetch drops the Authorization header on that cross-origin hop.
    const res = await fetch(`https://registry-1.docker.io/v2/${r.repo}/${kind}/${digest}`, { headers: H(accept) });
    if (!res.ok) throw new Error(`${kind} ${digest.slice(0, 19)}… HTTP ${res.status}`);
    return Buffer.from(await res.arrayBuffer());
  };
  const say = {};
  try {
    const index = await get('manifests', r.digest, INDEX_TYPES);
    fs.writeFileSync(path.join(out, 'index.raw'), index); say.index_bytes = index.length;
    const d = amd64Descriptor(JSON.parse(index.toString('utf8')));
    if (!d) throw new Error('the index lists no single linux/amd64 manifest');
    const manifest = await get('manifests', d.digest, MANIFEST_TYPES);
    fs.writeFileSync(path.join(out, 'manifest.raw'), manifest); say.manifest_bytes = manifest.length;
    const cd = JSON.parse(manifest.toString('utf8'))?.config?.digest;
    if (!/^sha256:[0-9a-f]{64}$/.test(String(cd))) throw new Error('the manifest names no sha256 config digest');
    const config = await get('blobs', cd, null);
    fs.writeFileSync(path.join(out, 'config.raw'), config); say.config_bytes = config.length;
    // Security 12327.1: every layer, by digest. A layer that fails to come (a rate limit included) stops the fetch, so
    // its file is missing and the layer verdict reads it as red.
    const layers = JSON.parse(manifest.toString('utf8'))?.layers;
    if (!Array.isArray(layers) || !layers.length) throw new Error('the manifest names no layers');
    if (flag === '--no-layers') { console.log(JSON.stringify({ fetched: true, layers_skipped: layers.length, ...say })); return 0; }
    fs.mkdirSync(path.join(out, 'layers'), { recursive: true });
    say.layers = 0; say.layer_bytes = 0;
    for (const [i, l] of layers.entries()) {
      if (!/^sha256:[0-9a-f]{64}$/.test(String(l?.digest))) throw new Error(`layer ${i} names no sha256 digest`);
      const b = await get('blobs', l.digest, null);
      fs.writeFileSync(path.join(out, 'layers', `${i}.blob`), b); say.layers += 1; say.layer_bytes += b.length;
    }
  } catch (e) {
    console.log(JSON.stringify({ fetched: false, why: e.message, ...say }));
    return 1;
  }
  console.log(JSON.stringify({ fetched: true, ...say }));
  return 0;
}

if (process.argv[1]?.endsWith('mediator-base-fetch.mjs')) {
  main(process.argv.slice(2)).then((c) => process.exit(c), (e) => { console.error(`mediator-base-fetch: ${e.message}`); process.exit(1); });
}
