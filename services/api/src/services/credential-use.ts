import type { Database } from '../db/pool.js';

/**
 * ============================================================================
 * Credential last-used tracking, off the request path.
 * ============================================================================
 *
 * `last_used_at` answers one operator question: "is anything still using this
 * credential, or can I revoke it?" It is telemetry. It was costing a database
 * transaction -- an fsync -- in front of every authenticated request, which
 * the latency baseline measured as roughly a quarter of the commits an
 * authorize pays for.
 *
 * So it moves off the hot path. `record()` puts an id in a set; a timer
 * flushes the set in one transaction. A node serving a thousand requests a
 * second against ten credentials writes ten rows a minute instead of a
 * thousand transactions a second.
 *
 * ## What this gives up, stated plainly
 *
 * `last_used_at` becomes **best-effort**. A process killed between flushes
 * loses up to one interval of tracking, so a credential used forty seconds ago
 * can read as unused after a crash.
 *
 * That is acceptable *because of what the column is for*. Nothing authorises
 * on it, nothing expires on it, and no decision reads it. The one operator
 * action it informs -- revoking a credential that looks idle -- is reversible
 * in fifteen seconds by issuing another. Compare that with what it was
 * costing, and the trade is not close.
 *
 * It would not be acceptable for `expires_at`, `revoked_at`, or anything the
 * authenticator reads, and none of those move. Authentication still reads the
 * credential row on the request's own connection, every time, with no cache:
 * revocation still takes effect on the very next request.
 *
 * ## Why not write it inside the request's own transaction instead
 *
 * That was the other option, and it is worse in the case that matters. The
 * request's transaction is the one that commits the decision and the receipt;
 * adding a write to an unrelated table to it widens what a rollback throws
 * away and puts an `api_credentials` row lock inside the same transaction that
 * holds the tenant's receipt chain head. Telemetry does not belong in the
 * transaction that moves money.
 */
export interface CredentialUseTracker {
  /** Note that a credential authenticated. Never throws, never awaits. */
  record(credentialId: string): void;
  /** Write everything buffered. Safe to call concurrently with `record`. */
  flush(): Promise<void>;
  /** Stop the timer and flush what is left. */
  close(): Promise<void>;
}

/**
 * Beyond this many distinct credentials in one interval, flush early rather
 * than grow. A node serving many tenants should not be able to turn a
 * telemetry buffer into a memory leak, and an early flush is the cheapest
 * possible answer to "the buffer is bigger than expected".
 */
const MAX_BUFFERED = 5_000;

export function startCredentialUseTracker(db: Database, intervalMs = 60_000): CredentialUseTracker {
  let buffered = new Set<string>();
  let closed = false;
  // Serialises flushes so an interval firing during a slow write does not
  // start a second one against the same rows.
  let inFlight: Promise<void> = Promise.resolve();

  const write = async (ids: string[]): Promise<void> => {
    if (ids.length === 0) return;
    await db.withoutTenant((client) =>
      client.query('SELECT scrutexity.touch_credentials($1::text[])', [ids]),
    );
  };

  const flush = async (): Promise<void> => {
    const pending = buffered;
    if (pending.size === 0) return inFlight;
    buffered = new Set();
    inFlight = inFlight
      .then(() => write([...pending]))
      // Losing telemetry must never surface as a failed request or an
      // unhandled rejection. The next flush picks up whatever is recorded
      // after it; the ids in this batch are simply not written.
      .catch(() => undefined);
    return inFlight;
  };

  const timer = setInterval(() => {
    void flush();
  }, intervalMs);
  // Never a reason to hold the process open. A pending flush is telemetry.
  timer.unref?.();

  return {
    record(credentialId: string): void {
      if (closed) return;
      buffered.add(credentialId);
      if (buffered.size >= MAX_BUFFERED) void flush();
    },
    flush,
    async close(): Promise<void> {
      closed = true;
      clearInterval(timer);
      await flush();
      await inFlight;
    },
  };
}
