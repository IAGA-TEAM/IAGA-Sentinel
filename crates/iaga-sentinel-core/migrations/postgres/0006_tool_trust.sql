-- 2.0.1 audit: persist AgentProfile.tool_trust. Postgres twin of the sqlite
-- migration of the same number; see that file for why the column was missing
-- and what was measured before it existed.
--
-- DOUBLE PRECISION matches the `f64` on `AgentProfile`. The default is the same
-- 0.7 that `default_tool_trust` supplies, so existing rows are scored exactly
-- as they are today and upgrading moves no signed byte.

ALTER TABLE agent_profiles ADD COLUMN IF NOT EXISTS tool_trust DOUBLE PRECISION NOT NULL DEFAULT 0.7;
