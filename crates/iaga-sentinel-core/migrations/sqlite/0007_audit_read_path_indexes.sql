-- D9. Composite indexes for the audit read path.
--
-- Both audit reads order by `created_at DESC, event_id DESC` — a total order,
-- because `event_id` is the PRIMARY KEY. `created_at` is now supplied by the
-- INSERT from the pipeline's own decision time at microsecond precision
-- (`storage::sqlite::audit_created_at`), so the leading column is the real
-- chronology and the tie-break is a last resort rather than the de-facto sort:
-- it used to default to `datetime('now')` — whole seconds — which meant a busy
-- second was ordered by a UUID. The only index that existed was
-- `idx_audit_created` on `created_at` alone, which cannot satisfy the tie-break:
-- SQLite reads the index for the leading column and then sorts each tie group.
--
-- Two indexes, one per read path:
--
--   * `/v1/audit`               -> unfiltered, ordered      -> (created_at, event_id)
--   * `/v1/audit/export?agent_id=…` -> filtered then ordered -> (agent_id, created_at, event_id)
--
-- The second is aspirational rather than load-bearing today, and saying so is
-- cheaper than someone re-deriving it: measured on SQLite 3.49 with 3000 rows
-- and ANALYZE, `EXPLAIN QUERY PLAN` for the real `list_filtered` SQL chooses
-- `SCAN audit_events USING INDEX idx_audit_created_event` — the planner prefers
-- satisfying the ORDER BY over the agent_id equality. It is kept because the
-- choice flips with selectivity and row count, and because the query it is
-- shaped for is the one an auditor pages through.
--
-- `idx_audit_agent` (agent_id alone) is left in place: it still serves the
-- equality predicate for queries that do not order, and dropping an index in a
-- migration is a change with no upside here.
--
-- SQLite honours DESC in an index definition from 3.8.3 onward and can also
-- scan an ASC index backwards, so the direction is written out to match the
-- query rather than relying on the reverse scan.
CREATE INDEX IF NOT EXISTS idx_audit_created_event
    ON audit_events(created_at DESC, event_id DESC);

CREATE INDEX IF NOT EXISTS idx_audit_agent_created_event
    ON audit_events(agent_id, created_at DESC, event_id DESC);
