/**
 * Server-authoritative time.
 *
 * An agent must never be able to influence expiry by lying about the clock, so
 * every lifetime check in the evaluator reads from a Clock passed in by the
 * caller. Tests inject a fixed clock; production injects the system clock.
 */
export interface Clock {
  now(): Date;
}

export const systemClock: Clock = { now: () => new Date() };

export function fixedClock(instant: Date | string | number): Clock {
  const at = new Date(instant);
  if (Number.isNaN(at.getTime())) throw new TypeError('invalid instant');
  return { now: () => new Date(at.getTime()) };
}

/** A clock that can be advanced by tests without sleeping. */
export function manualClock(start: Date | string | number = 0): Clock & {
  advance(ms: number): void;
  set(instant: Date | string | number): void;
} {
  let current = new Date(start).getTime();
  return {
    now: () => new Date(current),
    advance: (ms) => {
      current += ms;
    },
    set: (instant) => {
      current = new Date(instant).getTime();
    },
  };
}

/**
 * Expiry is inclusive of the boundary: an instant exactly equal to
 * `expires_at` is already expired. A lease must never authorise at the moment
 * it lapses, and the tie has to break the safe way.
 */
export function isExpired(expiresAt: Date | string, now: Date): boolean {
  return new Date(expiresAt).getTime() <= now.getTime();
}

export function addSeconds(instant: Date, seconds: number): Date {
  return new Date(instant.getTime() + seconds * 1000);
}

export function toIso(instant: Date): string {
  return instant.toISOString();
}
