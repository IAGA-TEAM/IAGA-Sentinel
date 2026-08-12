-- D9. Composite indexes for the audit read path. Twin of the SQLite 0007.
--
-- Both audit reads order by `created_at DESC, event_id DESC`. `created_at` is
-- `TIMESTAMPTZ DEFAULT NOW()` here rather than whole-second text, so exact ties
-- are rarer than on SQLite — but the tie-break is what makes the order TOTAL,
-- and an index that stops at `created_at` leaves the planner to sort whatever
-- shares a value. The two backends must also agree on the page they return for
-- the same data, which they cannot do if only one of them has a total order
-- available.
--
-- Kept in lockstep with the SQLite migration number so `iaga migrate` reports
-- the same version on either backend.
CREATE INDEX IF NOT EXISTS idx_audit_created_event
    ON audit_events(created_at DESC, event_id DESC);

CREATE INDEX IF NOT EXISTS idx_audit_agent_created_event
    ON audit_events(agent_id, created_at DESC, event_id DESC);
