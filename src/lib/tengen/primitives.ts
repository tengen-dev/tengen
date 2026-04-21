const subtle: SubtleCrypto =
  (globalThis.crypto && globalThis.crypto.subtle) ??
  (() => {
    throw new Error('tengen: SubtleCrypto unavailable in this runtime');
  })();

export const randomBytes = (n: number): Uint8Array => {
  const buf = new Uint8Array(n);
  globalThis.crypto.getRandomValues(buf);
  return buf;
};

export const zeroize = (...bufs: (Uint8Array | ArrayBuffer | undefined | null)[]): void => {
  for (const b of bufs) {
    if (!b) continue;
    const view = b instanceof ArrayBuffer ? new Uint8Array(b) : b;
    view.fill(0);
  }
};

export const concat = (...parts: Uint8Array[]): Uint8Array => {
  const total = parts.reduce((s, p) => s + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
};

export const ctEqual = (a: Uint8Array, b: Uint8Array): boolean => {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return diff === 0;
};

export const hkdf = async (
  ikm: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  lenBytes: number,
): Promise<Uint8Array> => {
  const key = await subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  const bits = await subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt, info },
    key,
    lenBytes * 8,
  );
  return new Uint8Array(bits);
};

export const hmacSha256 = async (key: Uint8Array, data: Uint8Array): Promise<Uint8Array> => {
  const k = await subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const mac = await subtle.sign('HMAC', k, data);
  return new Uint8Array(mac);
};

export const sha256 = async (data: Uint8Array): Promise<Uint8Array> => {
  const h = await subtle.digest('SHA-256', data);
  return new Uint8Array(h);
};

export const aesGcmEncrypt = async (
  key: Uint8Array,
  iv: Uint8Array,
  plaintext: Uint8Array,
  aad?: Uint8Array,
): Promise<Uint8Array> => {
  const k = await subtle.importKey('raw', key, 'AES-GCM', false, ['encrypt']);
  const ct = await subtle.encrypt(
    aad ? { name: 'AES-GCM', iv, additionalData: aad } : { name: 'AES-GCM', iv },
    k,
    plaintext,
  );
  return new Uint8Array(ct);
};

export const aesGcmDecrypt = async (
  key: Uint8Array,
  iv: Uint8Array,
  ciphertext: Uint8Array,
  aad?: Uint8Array,
): Promise<Uint8Array> => {
  const k = await subtle.importKey('raw', key, 'AES-GCM', false, ['decrypt']);
  const pt = await subtle.decrypt(
    aad ? { name: 'AES-GCM', iv, additionalData: aad } : { name: 'AES-GCM', iv },
    k,
    ciphertext,
  );
  return new Uint8Array(pt);
};

export const b64u = {
  encode(bytes: Uint8Array): string {
    let s = '';
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]!);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  },
  decode(str: string): Uint8Array {
    const pad = str.length % 4 === 0 ? '' : '='.repeat(4 - (str.length % 4));
    const s = atob(str.replace(/-/g, '+').replace(/_/g, '/') + pad);
    const out = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
    return out;
  },
};
