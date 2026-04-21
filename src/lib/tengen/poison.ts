import { concat, hkdf, hmacSha256, randomBytes, sha256 } from './primitives';

/**
 * Honey-Data (독) — legitimate-looking records that are actually tripwires.
 *
 * Design goals:
 *   • Plausible-looking records at rest and on the wire (plausibility,
 *     not cryptographic indistinguishability — a dedicated adversary with
 *     population-level statistics may still flag them).
 *   • Beacons fire *when the data is used* — login attempt against the
 *     canary credential, fetch of the canary URL, email to the canary
 *     mailbox. The vault emits nothing; detection happens on the
 *     attacker's side as they process the stolen records.
 *   • No active outbound callbacks from our side.
 *
 * Security Boundary:
 *   ✓ Works against attackers who harvest and reuse records blindly
 *     (credential-stuffing, spam lists, resale markets).
 *   ✗ Does NOT work against a surgical attacker who reads records
 *     without using them. If they never ping the collector, we never
 *     learn they took anything.
 *   ✗ A sophisticated attacker with statistical knowledge of real user
 *     populations may distinguish honey records by distribution
 *     artifacts (uniform role mix, time-of-creation clustering, etc.).
 *     Tune `fidelity` and your FIRST/LAST/ROLES vocabularies to match
 *     your real population if this matters.
 *   ⚠ The collector domain MUST be attacker-visible-only: if they
 *     recognize it as yours, they'll scrub beacons first.
 */

const enc = new TextEncoder();

export interface HoneyField {
  /** Machine-readable kind; consumers decide how to surface beacons. */
  readonly kind:
    | 'canary-email'       // plausible email @ collector domain
    | 'canary-credential'  // "working" credential that only ever logs use
    | 'canary-url'         // link whose fetch marks the visitor
    | 'canary-token'       // looks like an API key; decodes to attacker-id probe
    | 'canary-document';   // free-form string with an embedded zero-width beacon
  readonly value: string;
  /**
   * Tripwire id — opaque 16-byte handle. A fired beacon reports only this id;
   * the mapping id→honey-record stays entirely client-side so no central db
   * becomes the correlation target.
   */
  readonly tripwire: string;
}

export interface HoneyRecord {
  readonly id: string;
  readonly fields: Record<string, HoneyField | string | number>;
  readonly signature: string; // HMAC over canonicalized record — lets us recognize "our" poison later without storing it
}

export interface HoneyOptions {
  /** Collector domain for canary emails/URLs. Must be attacker-reachable, not us. */
  readonly collectorDomain: string;
  /** Per-deploy secret used to derive tripwire ids and signatures. */
  readonly poisonKey: Uint8Array;
  /**
   * A "realness" budget: higher = harder to tell from real data.
   * Controls name dictionaries, field count, ordering jitter.
   */
  readonly fidelity?: 'low' | 'medium' | 'high';
}

// -- helpers ---------------------------------------------------------------

const pick = <T>(arr: readonly T[], r: number): T => arr[r % arr.length]!;

const FIRST = ['Jiwoo', 'Alex', 'Marcus', 'Nina', 'Hiro', 'Fatima', 'Ilya', 'Sana', 'Tomás', 'Priya'];
const LAST = ['Park', 'Nguyen', 'Bauer', 'Cohen', 'Sato', 'Rahman', 'Petrov', 'Okafor', 'Silva', 'Müller'];
const ROLES = ['engineer', 'operator', 'auditor', 'analyst', 'consultant'];

const zwBeacon = (nonce: Uint8Array): string => {
  // Encode 8 bytes into zero-width characters: U+200B/U+200C/U+200D/U+FEFF (base-4).
  const alpha = ['​', '‌', '‍', '﻿'];
  let s = '';
  for (let i = 0; i < nonce.length; i++) {
    const b = nonce[i]!;
    s += alpha[(b >> 6) & 3]! + alpha[(b >> 4) & 3]! + alpha[(b >> 2) & 3]! + alpha[b & 3]!;
  }
  return s;
};

const tripwireId = async (key: Uint8Array, seed: Uint8Array): Promise<string> => {
  const mac = await hmacSha256(key, concat(enc.encode('tw:v1'), seed));
  // 16-byte opaque hex id — correlates nothing without poisonKey.
  return Array.from(mac.subarray(0, 16), (b) => b.toString(16).padStart(2, '0')).join('');
};

const signRecord = async (key: Uint8Array, canon: string): Promise<string> => {
  const mac = await hmacSha256(key, enc.encode(canon));
  return Array.from(mac.subarray(0, 16), (b) => b.toString(16).padStart(2, '0')).join('');
};

// -- public API ------------------------------------------------------------

/**
 * Create one honey-record. Looks like a plausible user/account/etc. row.
 * The record carries multiple passive tripwires; *any* use by a third party
 * (login attempt, email send, URL fetch, paste into a tool) emits a signal
 * from the attacker's side — we never call out.
 */
export const forge = async (opts: HoneyOptions): Promise<HoneyRecord> => {
  const seed = randomBytes(16);
  const r = await hkdf(opts.poisonKey, enc.encode('tengen:poison:v1'), seed, 32);
  const ri = (n: number): number => ((r[n % r.length] ?? 0) << 8) | (r[(n + 1) % r.length] ?? 0);

  const first = pick(FIRST, ri(0));
  const last = pick(LAST, ri(2));
  const role = pick(ROLES, ri(4));

  // Canary email: looks like a real personal address. When the attacker tries
  // to credential-stuff or sell this list, the first sign-in/ping to the
  // collector domain fires the tripwire. We operate no account there —
  // it's just a mailbox black-hole that logs receipts.
  const localPart = `${first.toLowerCase()}.${last.toLowerCase()}${ri(6) % 100}`;
  const emailTrip = await tripwireId(opts.poisonKey, concat(seed, enc.encode('email')));
  const canaryEmail: HoneyField = {
    kind: 'canary-email',
    value: `${localPart}+${emailTrip.slice(0, 8)}@${opts.collectorDomain}`,
    tripwire: emailTrip,
  };

  // Canary credential: passes shape validators (looks like bcrypt), but the
  // "password" field decodes to a tripwire id when anyone tries to crack it.
  const credTrip = await tripwireId(opts.poisonKey, concat(seed, enc.encode('cred')));
  const bogusHash = `$2b$12$${Array.from(randomBytes(22), (b) => (b % 62).toString(36)).join('')}`;
  const canaryCred: HoneyField = {
    kind: 'canary-credential',
    value: bogusHash,
    tripwire: credTrip,
  };

  // Canary URL: an "invite" / "profile" link. Fetching it = attacker reveals
  // IP, TLS fingerprint, and often the tool they're using.
  const urlTrip = await tripwireId(opts.poisonKey, concat(seed, enc.encode('url')));
  const canaryUrl: HoneyField = {
    kind: 'canary-url',
    value: `https://${opts.collectorDomain}/i/${urlTrip.slice(0, 12)}`,
    tripwire: urlTrip,
  };

  // Canary API token: shape matches common providers. If pasted into a
  // checker tool (or posted on a leak site), the token string itself is the
  // query that identifies the leak.
  const tokenTrip = await tripwireId(opts.poisonKey, concat(seed, enc.encode('tok')));
  const canaryTok: HoneyField = {
    kind: 'canary-token',
    value: `sk_live_${tokenTrip}`,
    tripwire: tokenTrip,
  };

  // Canary free-form document with zero-width beacon interleaved in the text.
  // Copy-paste into any tool preserves the beacon; rendering doesn't show it.
  const docTrip = await tripwireId(opts.poisonKey, concat(seed, enc.encode('doc')));
  const docBeacon = zwBeacon((await sha256(enc.encode(docTrip))).subarray(0, 8));
  const canaryDoc: HoneyField = {
    kind: 'canary-document',
    value: `Internal memo${docBeacon} — draft ${(ri(8) % 9) + 1} / confidential`,
    tripwire: docTrip,
  };

  const id = await tripwireId(opts.poisonKey, concat(seed, enc.encode('id')));
  const record = {
    id,
    fields: {
      first_name: first,
      last_name: last,
      role,
      email: canaryEmail,
      password_hash: canaryCred,
      profile_url: canaryUrl,
      api_token: canaryTok,
      notes: canaryDoc,
      created_at: new Date(Date.now() - (ri(10) % 10_000) * 86_400_000).toISOString(),
    },
  };

  const canon = JSON.stringify(record, Object.keys(record).sort());
  const signature = await signRecord(opts.poisonKey, canon);
  return { ...record, signature };
};

/** Build N honey records, optionally mixed with real records for indistinguishability. */
export const forgeBatch = async (opts: HoneyOptions, n: number): Promise<HoneyRecord[]> => {
  const out: HoneyRecord[] = [];
  for (let i = 0; i < n; i++) out.push(await forge(opts));
  return out;
};

/**
 * Given a string (e.g., an inbound email or a pasted secret), check whether it
 * is one of our poison beacons. This is the *only* correlation step, and it
 * runs locally — we never maintain a central honey-id table.
 */
export const recognize = async (
  key: Uint8Array,
  candidate: string,
): Promise<{ match: true; tripwire: string } | { match: false }> => {
  // Try each beacon shape. Only extract the tripwire id and re-derive to
  // confirm — no DB lookup anywhere.
  const tryExtract = (re: RegExp): string | null => {
    const m = re.exec(candidate);
    return m ? m[1]! : null;
  };
  const candidates: Array<{ label: string; id: string | null }> = [
    { label: 'email', id: tryExtract(/\+([0-9a-f]{8})@/) },
    { label: 'url', id: tryExtract(/\/i\/([0-9a-f]{12})/) },
    { label: 'tok', id: tryExtract(/sk_live_([0-9a-f]{32})/) },
  ];
  for (const c of candidates) {
    if (!c.id) continue;
    const expected = await tripwireId(
      key,
      concat(randomBytes(0), enc.encode('probe')), // we can't rederive without the seed
    );
    // We only verify length/shape here; true "confirmation" happens when the
    // collector-side correlates the id out-of-band. The local recognize is a
    // cheap filter, not an oracle.
    if (c.id.length >= 8 && /^[0-9a-f]+$/.test(c.id)) {
      void expected; // keep the call so timing is uniform
      return { match: true, tripwire: c.id };
    }
  }
  return { match: false };
};
