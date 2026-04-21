import { z, type ZodTypeAny } from 'zod';
import { zeroize } from './primitives';
import { canonicalize, jitteredDelay, silent } from './ward';

/**
 * Entrance — the public-facing request handler.
 *
 * Invariants enforced by the shape of this module:
 *   1.  No database connection. This module imports no driver, no ORM,
 *       no connection string. The attack surface for SQL injection is
 *       absent from this process because the targets don't exist.
 *   2.  Inputs live in memory for one `handle()` call; buffers are
 *       zeroize()'d on the way out — success OR failure.
 *   3.  All exits converge on one response shape + timing via silent().
 *   4.  No logging, no metrics, no tracing, no writes.
 *
 * Security Boundary:
 *   ✓ SQL injection surface is nil for this process. (It may still exist
 *     in whatever downstream service consumes the output of handle().)
 *   ✓ Uniform-shape error responses prevent cheap probing for existence.
 *   ✗ zeroize() on input buffers does not guarantee the bytes have left
 *     V8's heap (see fragment.ts note on the JS memory model).
 *   ✗ This module does NOT protect against application-logic bugs in
 *     the user-supplied `handler()` — Zod-validated input can still be
 *     misused by the callback.
 *   ⚠ jitteredDelay() adds a 40–100ms tail. Benchmarks will reflect that
 *     cost; it is intentional.
 */

export interface EntranceRequest {
  readonly path: string;
  readonly method: string;
  readonly headers: Readonly<Record<string, string>>;
  readonly body: Uint8Array;
}

export type EntranceHandler<S extends ZodTypeAny, R> = (
  input: z.infer<S>,
  ctx: { nowMs: number },
) => Promise<R>;

export interface EntranceOptions<S extends ZodTypeAny, R> {
  readonly schema: S;
  readonly parseBody: (raw: Uint8Array) => unknown;
  readonly handler: EntranceHandler<S, R>;
  readonly encode: (value: R) => Uint8Array;
}

/** Build a locked-down entrance function. */
export const makeEntrance =
  <S extends ZodTypeAny, R>(opts: EntranceOptions<S, R>) =>
  async (req: EntranceRequest): Promise<Response> => {
    const scratch: Uint8Array[] = [req.body];
    try {
      let parsed: unknown;
      try {
        parsed = opts.parseBody(req.body);
      } catch {
        await jitteredDelay();
        return silent();
      }
      const canonical = normalizeDeep(parsed);
      const result = opts.schema.safeParse(canonical);
      if (!result.success) {
        await jitteredDelay();
        return silent();
      }
      const output = await opts.handler(result.data, { nowMs: Date.now() });
      const body = opts.encode(output);
      scratch.push(body);
      await jitteredDelay();
      return new Response(body, {
        status: 200,
        headers: {
          'Content-Type': 'application/octet-stream',
          'Cache-Control': 'no-store',
        },
      });
    } catch {
      await jitteredDelay();
      return silent();
    } finally {
      // Memory scrub — every buffer that touched user input gets zeroized.
      for (const b of scratch) zeroize(b);
    }
  };

const normalizeDeep = (v: unknown): unknown => {
  if (typeof v === 'string') return canonicalize(v);
  if (Array.isArray(v)) return v.map(normalizeDeep);
  if (v && typeof v === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, val] of Object.entries(v as Record<string, unknown>)) {
      out[canonicalize(k)] = normalizeDeep(val);
    }
    return out;
  }
  return v;
};
