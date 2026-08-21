/**
 * @scrutexity/core -- the deterministic heart of the control plane.
 *
 * Everything exported here is pure. No database handle, no HTTP client and no
 * clock reaches this package; callers pass facts in and receive decisions and
 * evidence out. That is the property that makes authorization decisions
 * replayable, testable in isolation, and identical across the SDK, the
 * sidecar, the gateway and the hosted service.
 */

export * from './ids.js';
export * from './canonical.js';
export * from './decimal.js';
export * from './money.js';
export * from './time.js';
export * from './errors.js';
export * from './actions.js';

export * from './authority/grant.js';
export * from './authority/lease.js';

export * from './policy/schema.js';
export * from './policy/predicate.js';
export * from './policy/engine.js';
export * from './policy/loader.js';

export * from './approval.js';
export * from './delegation.js';
export * from './evaluate.js';
export * from './receipts.js';
export * from './explain.js';
