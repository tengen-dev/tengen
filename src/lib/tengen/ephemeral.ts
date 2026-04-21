import { b64u, concat, ctEqual, hkdf, hmacSha256, randomBytes, zeroize } from './primitives';

// Ephemeral session secret — held only in RAM, wiped on disconnect.
// All derived keys are HKDF(sessionSecret, salt=purpose, info=context).

const enc = new TextEncoder();

export interface EphemeralSession {
  readonly secret: Uint8Array;       // 32 bytes, never transmitted
  readonly id: Uint8Array;           // 16 bytes, opaque public handle
  readonly bornAt: number;           // ms epoch
  readonly ttlMs: number;
  burn(): void;
}

export const createSession = (ttlMs = 60_000): EphemeralSession => {
  const secret = randomBytes(32);
  const id = randomBytes(16);
  const bornAt = Date.now();
  let alive = true;
  return {
    secret,
    id,
    bornAt,
    ttlMs,
    burn() {
      if (!alive) return;
      alive = false;
      zeroize(secret, id);
    },
  };
};

export const deriveSubkey = async (
  session: EphemeralSession,
  purpose: string,
  context: Uint8Array = new Uint8Array(0),
  lenBytes = 32,
): Promise<Uint8Array> => {
  return hkdf(session.secret, enc.encode(`tengen:${purpose}`), context, lenBytes);
};

// -------- Ephemeral one-shot route ---------------------------------------
// Route = base64url( ts_be64 ∥ nonce16 ∥ mac16 )
//   where mac = HMAC(routeKey, "R" ∥ ts ∥ nonce)[:16]
// Server recomputes mac; any mismatch → route treated as nonexistent (silent decoy).

const ROUTE_SALT = enc.encode('tengen:route:v1');

const be64 = (ms: number): Uint8Array => {
  const b = new Uint8Array(8);
  const hi = Math.floor(ms / 2 ** 32);
  const lo = ms >>> 0;
  new DataView(b.buffer).setUint32(0, hi);
  new DataView(b.buffer).setUint32(4, lo);
  return b;
};

const readBe64 = (b: Uint8Array): number => {
  const dv = new DataView(b.buffer, b.byteOffset, 8);
  return dv.getUint32(0) * 2 ** 32 + dv.getUint32(4);
};

export const mintRoute = async (session: EphemeralSession): Promise<string> => {
  const routeKey = await hkdf(session.secret, ROUTE_SALT, session.id, 32);
  const ts = be64(Date.now());
  const nonce = randomBytes(16);
  const mac = (await hmacSha256(routeKey, concat(enc.encode('R'), ts, nonce))).slice(0, 16);
  zeroize(routeKey);
  return b64u.encode(concat(ts, nonce, mac));
};

export const verifyRoute = async (
  session: EphemeralSession,
  token: string,
  now = Date.now(),
): Promise<boolean> => {
  let decoded: Uint8Array;
  try {
    decoded = b64u.decode(token);
  } catch {
    return false;
  }
  if (decoded.length !== 40) return false;
  const ts = decoded.subarray(0, 8);
  const nonce = decoded.subarray(8, 24);
  const mac = decoded.subarray(24, 40);
  const age = now - readBe64(ts);
  if (age < 0 || age > session.ttlMs) return false;

  const routeKey = await hkdf(session.secret, ROUTE_SALT, session.id, 32);
  const expected = (await hmacSha256(routeKey, concat(enc.encode('R'), ts, nonce))).slice(0, 16);
  zeroize(routeKey);
  return ctEqual(mac, expected);
};
