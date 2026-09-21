-- Token roles: agent tokens only ever see their own session's requests,
-- operator tokens audit everything. Every token that predates roles was
-- issued through the same pairing flow as today's agents, but revoking
-- visibility for existing deployments would silently break running
-- operators — so the migration keeps them operator and README documents
-- the re-issue path.
ALTER TABLE auth_tokens ADD COLUMN role TEXT NOT NULL DEFAULT 'operator';
