import {
  aesGcmDecrypt,
  aesGcmEncrypt,
  b64u,
  concat,
  hkdf,
  hmacSha256,
  randomBytes,
  zeroize,
} from './primitives';
import { combine, split, type Share } from './shamir';
import type { EphemeralSession } from './ephemeral';

/**
 * Tengen Shatter/Scatter (metadata-less)
 * --------------------------------------
 *   1.  Outer data is AES-256-GCM encrypted with a random DEK, bound to the
 *       session via AAD.
 *   2.  DEK is split by Shamir k-of-n — any k-1 shares reveal nothing.
 *   3.  Ciphertext is chunked; each chunk is re-encrypted under a subkey
 *       derived from that shard's address. The IV is *also* derived from
 *       the address, so the wire blob is pure ciphertext + GCM tag — no
 *       version byte, no IV prefix, no header.
 *   4.  Shard addresses are salt-derived; the manifest carries only the
 *       salts (and Shamir y-values). Without the session secret the
 *       manifest cannot produce the addresses it refers to.
 *   5.  The manifest itself is delivered as one more encrypted envelope
 *       keyed by a client-held key.
 *
 * Security Boundary:
 *   ✓ A single shard, without the session secret, is computationally
 *     indistinguishable from random bytes at rest.
 *   ✓ The manifest without the client key reveals no addresses.
 *   ✓ k-1 shards reveal nothing about the plaintext (information-
 *     theoretic, from Shamir).
 *   ✗ This layer protects AT REST. It does NOT hide the fact that shards
 *     are being accessed — that's the oblivious-fetch layer's job
 *     (see integrity.ts:obliviousFetchAll).
 *   ✗ Loss of the client key is permanent data loss; there is no recovery
 *     path. Pair with quorum.ts if you need shared custody of the client
 *     key itself.
 */

const enc = new TextEncoder();

export interface ShardBlob {
  /** Content-addressed handle. 32 bytes as url-safe base64. */
  readonly addr: string;
  /** Encrypted shard payload (raw ciphertext + GCM tag, no header). */
  readonly body: Uint8Array;
  /** Which backend the client chose. Re-derived from addr at read-time. */
  readonly backend: number;
}

/**
 * A manifest that never contains addresses or backend ids in the clear.
 * Only the salts and the y-values of the Shamir shares. Addresses and
 * backends are re-derived at open-time from (session.secret, salt).
 */
export interface ShatterManifest {
  readonly k: number;
  readonly n: number;
  readonly size: number;
  readonly iv: Uint8Array;
  /** Shamir shares — y-values only; x values live with the salt entries. */
  readonly shares: ReadonlyArray<{ x: number; y: Uint8Array }>;
  /** One 16-byte salt per real shard, in chunk order. */
  readonly salts: readonly Uint8Array[];
}

/** Encrypted manifest blob — the only thing the client needs to open a vault. */
export interface ManifestEnvelope {
  readonly body: Uint8Array; // AES-GCM ciphertext of the serialized manifest
  readonly iv: Uint8Array;   // 12 bytes
}

export interface ScatterOptions {
  k?: number;
  n?: number;
  decoys?: number;
  backends?: number;
}

const defaultOpts = (o: ScatterOptions | undefined): Required<ScatterOptions> => {
  const n = o?.n ?? 5;
  const k = o?.k ?? Math.max(2, Math.ceil((n * 2) / 3));
  return {
    n,
    k,
    decoys: o?.decoys ?? Math.max(n, 8),
    backends: o?.backends ?? 3,
  };
};

// ---- Address / key / backend derivation (all session-gated) --------------

const addrFromSalt = async (session: EphemeralSession, salt: Uint8Array): Promise<Uint8Array> =>
  (
    await hmacSha256(
      await hkdf(session.secret, enc.encode('tengen:addr:v1'), session.id, 32),
      concat(enc.encode('A'), salt),
    )
  ).slice(0, 32);

const ivFromAddr = async (session: EphemeralSession, addr: Uint8Array): Promise<Uint8Array> =>
  (await hkdf(session.secret, enc.encode('tengen:iv:v1'), addr, 12));

const keyFromAddr = async (session: EphemeralSession, addr: Uint8Array): Promise<Uint8Array> =>
  hkdf(session.secret, enc.encode('tengen:shard:v1'), addr, 32);

const pickBackend = async (
  session: EphemeralSession,
  addr: Uint8Array,
  backends: number,
): Promise<number> => {
  const h = await hmacSha256(
    await hkdf(session.secret, enc.encode('tengen:route:v1'), session.id, 32),
    concat(enc.encode('B'), addr),
  );
  const dv = new DataView(h.buffer, h.byteOffset, 4);
  return dv.getUint32(0) % backends;
};

// ---- shatter() -----------------------------------------------------------

export interface ShatterResult {
  readonly manifest: ShatterManifest;
  readonly blobs: readonly ShardBlob[];
}

export const shatter = async (
  session: EphemeralSession,
  data: Uint8Array,
  opts?: ScatterOptions,
): Promise<ShatterResult> => {
  if (data.length === 0) throw new Error('shatter: empty data');
  const { k, n, decoys, backends } = defaultOpts(opts);
  if (n < k || k < 2 || n > 200) throw new Error('shatter: invalid (k,n)');

  const dek = randomBytes(32);
  const iv = randomBytes(12);
  const aad = concat(enc.encode('tengen:data:v1'), session.id);
  const cipher = await aesGcmEncrypt(dek, iv, data, aad);

  const keyShares = split(dek, k, n);
  zeroize(dek);

  // Every chunk is padded to exactly chunkSize so that every blob body
  // ends up at chunkSize + 16 bytes (GCM tag). Without this, the last
  // chunk would be shorter and stand out in the size histogram (audit
  // finding H). The true ciphertext length lives in manifest.size and
  // is used at reassemble-time to strip the zero padding before the
  // outer AES-GCM decrypt.
  const chunkSize = Math.ceil(cipher.length / n);
  const realBlobs: ShardBlob[] = [];
  const salts: Uint8Array[] = [];

  for (let i = 0; i < n; i++) {
    const slice = cipher.subarray(i * chunkSize, Math.min((i + 1) * chunkSize, cipher.length));
    const chunk = new Uint8Array(chunkSize);
    chunk.set(slice); // trailing bytes stay zero-filled
    const salt = randomBytes(16);
    const addr = await addrFromSalt(session, salt);
    const shardKey = await keyFromAddr(session, addr);
    const shardIv = await ivFromAddr(session, addr);
    // AAD = addr only — no index, no Shamir x, no session-id in the blob.
    const body = await aesGcmEncrypt(shardKey, shardIv, chunk, addr);
    zeroize(shardKey);
    zeroize(chunk);
    const backend = await pickBackend(session, addr, backends);
    realBlobs.push({ addr: b64u.encode(addr), body, backend });
    salts.push(salt);
  }

  // Decoys: uniformly random bytes at uniformly random addresses.
  // Size matches the padded chunk + GCM tag exactly, so size never leaks
  // real-vs-decoy.
  const realSize = realBlobs[0]?.body.length ?? chunkSize + 16;
  const decoyBlobs: ShardBlob[] = [];
  for (let i = 0; i < decoys; i++) {
    const fakeAddr = randomBytes(32);
    const body = randomBytes(realSize);
    const backend = Math.floor(Math.random() * backends);
    decoyBlobs.push({ addr: b64u.encode(fakeAddr), body, backend });
  }

  const all = [...realBlobs, ...decoyBlobs];
  for (let i = all.length - 1; i > 0; i--) {
    const r = randomBytes(4);
    const j = ((r[0]! << 24) | (r[1]! << 16) | (r[2]! << 8) | r[3]!) >>> 0;
    const idx = j % (i + 1);
    [all[i], all[idx]] = [all[idx]!, all[i]!];
  }

  const shares = keyShares.map((s) => ({ x: s.x, y: s.y }));
  return {
    manifest: { k, n, size: data.length, iv, shares, salts },
    blobs: all,
  };
};

// ---- reassemble() --------------------------------------------------------

export type BlobFetcher = (addr: string, backend: number) => Promise<Uint8Array | null>;

export const reassemble = async (
  session: EphemeralSession,
  manifest: ShatterManifest,
  fetchBlob: BlobFetcher,
): Promise<Uint8Array> => {
  if (manifest.salts.length !== manifest.n) throw new Error('reassemble: salt/n mismatch');
  if (manifest.shares.length !== manifest.n) throw new Error('reassemble: share/n mismatch');

  const chunks: Uint8Array[] = new Array(manifest.n);
  let recovered = 0;

  for (let i = 0; i < manifest.n; i++) {
    const salt = manifest.salts[i]!;
    const addr = await addrFromSalt(session, salt);
    const backend = await pickBackend(session, addr, 3); // backends count is deploy-wide; expose if needed
    const body = await fetchBlob(b64u.encode(addr), backend);
    if (!body) continue;
    const shardKey = await keyFromAddr(session, addr);
    const shardIv = await ivFromAddr(session, addr);
    try {
      chunks[i] = await aesGcmDecrypt(shardKey, shardIv, body, addr);
      recovered++;
    } catch {
      // decoy or tampered — silently skip
    } finally {
      zeroize(shardKey);
    }
  }

  if (recovered < manifest.k) throw new Error('reassemble: below threshold');
  for (let i = 0; i < manifest.n; i++) {
    if (!chunks[i]) throw new Error('reassemble: missing chunk');
  }

  const shares: Share[] = manifest.shares.slice(0, manifest.k).map((s) => ({ x: s.x, y: s.y }));
  const dek = combine(shares);
  try {
    // Chunks are zero-padded to uniform size during shatter() (finding H).
    // Strip padding by truncating the concatenation to the true ciphertext
    // length = plaintext size + GCM tag (16).
    const padded = concat(...chunks);
    const cipher = padded.subarray(0, manifest.size + 16);
    const aad = concat(enc.encode('tengen:data:v1'), session.id);
    return await aesGcmDecrypt(dek, manifest.iv, cipher, aad);
  } finally {
    zeroize(dek);
  }
};

// ---- Manifest envelope (client-held key) --------------------------------

/**
 * Wrap the manifest in an AES-GCM envelope keyed by a client-held secret.
 * The envelope is the ONLY persistent pointer to a vault; if the client
 * loses their key, the vault is gone. The server stores the envelope as
 * opaque bytes and can't tell it from any other blob.
 */
export const sealManifest = async (
  m: ShatterManifest,
  clientKey: Uint8Array,
): Promise<ManifestEnvelope> => {
  const iv = randomBytes(12);
  const serialized = serializeManifest(m);
  const body = await aesGcmEncrypt(clientKey, iv, serialized, enc.encode('tengen:manifest:v1'));
  return { body, iv };
};

export const openManifest = async (
  env: ManifestEnvelope,
  clientKey: Uint8Array,
): Promise<ShatterManifest> => {
  const pt = await aesGcmDecrypt(clientKey, env.iv, env.body, enc.encode('tengen:manifest:v1'));
  return deserializeManifest(pt);
};

// Minimal length-prefixed serializer — deterministic, no JSON surface.
const serializeManifest = (m: ShatterManifest): Uint8Array => {
  const parts: Uint8Array[] = [];
  const u32 = (n: number) => {
    const b = new Uint8Array(4);
    new DataView(b.buffer).setUint32(0, n);
    return b;
  };
  parts.push(new Uint8Array([m.k, m.n]));
  parts.push(u32(m.size));
  parts.push(m.iv);
  for (const s of m.shares) {
    parts.push(new Uint8Array([s.x]));
    parts.push(u32(s.y.length));
    parts.push(s.y);
  }
  for (const salt of m.salts) parts.push(salt);
  return concat(...parts);
};

const deserializeManifest = (b: Uint8Array): ShatterManifest => {
  let off = 0;
  const k = b[off++]!;
  const n = b[off++]!;
  const dv = new DataView(b.buffer, b.byteOffset);
  const size = dv.getUint32(off);
  off += 4;
  const iv = b.slice(off, off + 12);
  off += 12;
  const shares: Array<{ x: number; y: Uint8Array }> = [];
  for (let i = 0; i < n; i++) {
    const x = b[off++]!;
    const yLen = dv.getUint32(off);
    off += 4;
    shares.push({ x, y: b.slice(off, off + yLen) });
    off += yLen;
  }
  const salts: Uint8Array[] = [];
  for (let i = 0; i < n; i++) {
    salts.push(b.slice(off, off + 16));
    off += 16;
  }
  return { k, n, size, iv, shares, salts };
};
