-- #157 Phase 2: fleet crash telemetry. Sanitized aggregates only —
-- {"ExcType:module:line": count} — never messages/tracebacks/paths.
-- Applied via: wrangler d1 migrations apply subarr-telemetry --remote (tracked in d1_migrations)
ALTER TABLE pings ADD COLUMN crashes_json TEXT;
