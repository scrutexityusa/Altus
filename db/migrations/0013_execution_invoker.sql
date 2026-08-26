-- ===========================================================================
-- 0013  Whose authority, and who pressed the button
-- ===========================================================================
--
-- `execution_claims.agent_id` records whose authority was consumed. It does
-- not record who asked for it to be consumed, and those are not the same
-- question. `/v1/execute` accepts any principal holding `authorization:evaluate`;
-- when that principal is not itself an agent, the agent is inferred from the
-- decision. So an operator-triggered execution was attributed to the agent,
-- and the operator appeared nowhere in the evidence.
--
-- That is a hole in the artifact, not merely in a table. A receipt that says
-- "this agent executed" when a human invoked the boundary on its behalf is
-- answering a question nobody asked while silently dropping the one an auditor
-- actually has. The receipt payload gains the same pair, so the verifiable
-- artifact carries it and not just the row.
--
-- Why NOT NULL with a sentinel rather than a nullable pair: a nullable pair
-- invites `if (invoker) { record(invoker) }`, which is exactly the shape of
-- omission that produced this gap. With the default dropped below, an INSERT
-- that forgets the invoker fails loudly instead of writing a blank.

SET search_path = scrutexity, public;

CREATE TYPE execution_invoker AS ENUM ('user', 'agent', 'service', 'unrecorded');

ALTER TABLE execution_claims
  ADD COLUMN invoked_by_type execution_invoker NOT NULL DEFAULT 'unrecorded',
  ADD COLUMN invoked_by_id   TEXT;

-- Rows written before this migration have no invoker to recover, and they say
-- so. Backfilling them to the agent would assert the one thing that was never
-- established: that the agent pressed its own button. 'unrecorded' is the
-- honest value, and it is distinguishable from every real principal.
ALTER TABLE execution_claims
  ADD CONSTRAINT execution_claims_invoker_complete CHECK (
    (invoked_by_type = 'unrecorded') = (invoked_by_id IS NULL)
  );

-- The default existed only to fill the rows that already existed. Dropping it
-- means a future INSERT that omits the invoker raises rather than recording a
-- claim whose provenance is a lie by omission.
ALTER TABLE execution_claims ALTER COLUMN invoked_by_type DROP DEFAULT;

-- Answering "everything this operator caused" without scanning the table.
CREATE INDEX execution_claims_invoked_by_idx
  ON execution_claims (organization_id, invoked_by_type, invoked_by_id)
  WHERE invoked_by_type <> 'unrecorded';
