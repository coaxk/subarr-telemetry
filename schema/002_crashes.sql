-- #157 Phase 2: fleet crash telemetry. Sanitized aggregates only —
-- {"ExcType:module:line": count} — never messages/tracebacks/paths.
-- Apply with: wrangler d1 execute subarr-telemetry --remote --file=schema/002_crashes.sql
ALTER TABLE pings ADD COLUMN crashes_json TEXT;
