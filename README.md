# Tengen

Research-grade stealth security architecture. A library for data sharding,
metadata-less storage, FROST threshold signing, and tamper-evident runtime
execution.

---

## ⚠️ STATUS: PRE-AUDIT RESEARCH CODE

**Do not use with data whose compromise would cause real-world harm.**

This code has NOT been reviewed by an independent cryptographic auditor.
The cryptographic primitives (AES-GCM, HKDF, Ed25519, X25519) come from
audited libraries (Web Crypto, `@noble/curves`, `@noble/hashes`), but the
protocol glue — FROST wrapper, Shamir x-coordinate Lagrange interpolation,
shatter/scatter encoding, update binding, Merkle canonicalization — is
original to this repository and has been reviewed only by the author and
the LLM that co-authored it.

Before using Tengen with any production data:

1. Commission an external cryptographic audit (Trail of Bits, NCC Group,
   Cure53, or similar). Budget USD $30–50k and 2–4 weeks.
2. Obtain legal counsel for your jurisdiction regarding data protection
   law, terms of service, and liability limitation.
3. Write an EULA that explicitly disclaims suitability for any purpose.
   Note that some jurisdictions void "as-is" disclaimers for
   consumer-facing software.
4. Run a time-limited closed pilot with internal data only and a
   documented incident-response plan.

No one associated with this repository — including AI co-authors — will
indemnify you against losses arising from use of this code. See LICENSE.

---

## Architecture

No UI. No database. No server-side state. Everything happens either at
build time, in RAM at runtime, or via offline cryptographic operations.

Components (alphabetical):

- **`channel.ts`** — output-chained PoW puzzle + 1 ms TTL key channel.
- **`deploy.ts`** — top-level `deploy() / run()` API.
- **`entrance.ts`** — DB-less public request handler factory.
- **`ephemeral.ts`** — per-session secret + one-shot route tokens.
- **`fragment.ts`** — source → shuffled blobs + encrypted entry envelope.
- **`frost.ts`** — FROST-Ed25519 threshold Schnorr (trusted-dealer).
- **`integrity.ts`** — Merkle root over blob set + `obliviousFetchAll()`.
- **`lightspeed.ts`** — great-circle RTT anomaly detector.
- **`maze.ts`** — deterministic decoy router.
- **`observer.ts`** — advisory debugger/devtools detection.
- **`poison.ts`** — honey-data record forging with passive tripwires.
- **`quorum.ts`** — m-of-n approval wrapper around FROST.
- **`shatter.ts`** — k-of-n Shamir DEK split + encrypted-shard scatter.
- **`updater.ts`** — FROST-signed + X25519-wrapped package handoff.
- **`ward.ts`** — Zod-gated input, sink-aware output encoding.
- **`dkg.ts`** — Pedersen distributed key generation (no trusted dealer).
- **`audit.ts`** — adversarial self-audit, runnable via `npm run audit`.
- **`fuzz.ts`** — randomized input harness, runnable via `npm run fuzz`.
- **`bench.ts`** — performance + bandwidth measurements, `npm run bench`.

Each file's top-of-file comment carries an explicit **Security Boundary**
block listing what it does and does NOT defend against.

## Layout

```
tengen/
├── src/
│   ├── lib/tengen/     Library modules + their unit + audit scripts
│   └── cli/tengen.ts   Command-line harness (deploy/run/verify/audit)
├── loader/             Go RAM-only loader (mlock + Ed25519 + scrub)
├── package.json
├── tsconfig.json
└── README.md (this file)
```

No `next/`, no `react/`, no `src/app/`, no `src/pages/`. UI code is an
unnecessary attack surface and has been deliberately omitted.

## Build & run

Requires **Node 22+** (the test runner relies on `node --test` glob support
that landed in 22).

```bash
npm install
npm run typecheck
npm test        # unit + integration tests
npm run audit   # adversarial audit script
npm run fuzz    # randomized input harness (~1–2 min at defaults)
npm run bench   # perf + oblivious-fetch multiplier table
```

An external cryptographic audit is a prerequisite for production use; see
`AUDIT_RFP.md` for scope and reviewer instructions.

## CLI

```bash
npm run tengen -- help

# Deploy a source file into a package directory
npm run tengen -- deploy mysource.txt ./pkg --nodes 64 --decoys 128

# Verify the Merkle root of a package (no execution)
npm run tengen -- verify ./pkg

# Execute the chain; reassembled source goes to stdout
npm run tengen -- run ./pkg > recovered.txt

# Run the adversarial audit
npm run tengen -- audit
```

`deploy` writes `entry.body`, `entry.iv`, `deploy.key`, `manifest.json`,
and one file per blob under `blobs/`. The `deploy.key` file is 32 bytes of
raw entropy; treat it as a password for the package.

## Threat model (what Tengen tries to defend against)

- Passive network observers of blobs at rest.
- Eavesdropping on update approval traffic.
- Reconnaissance scans probing for real vs decoy blobs.
- Per-byte tampering of blobs between build and run.
- Bait-and-switch of update bundles.
- Casual devtools / debugger attachment.

## Non-goals (what Tengen does NOT defend against)

- Side-channel attacks (power, EM, cache, branch prediction).
- Compromise of the signer's own long-term key material.
- A determined reverse engineer on the runtime host (use hardware
  enclaves for that tier).
- Denial of service (availability is not a design goal).
- Sovereign / legal compulsion of signers.

## Contributing

Issue reports and adversarial test cases welcome. Do not submit code that
removes Security Boundary comments, adds UI, reintroduces database
dependencies, or widens the threat-model claims without a corresponding
cryptographic proof.
