-- Agent-scoped keys may assert exactly one agent identity. Existing admin keys
-- remain valid; existing unbound agent keys fail closed until rotated.
-- ponytail: one nullable column is the whole mapping. Issuance validates it and
-- authorization fails closed; no join table or profile FK, because operators
-- may mint a key before importing that agent's profile.
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS agent_id TEXT DEFAULT NULL;
