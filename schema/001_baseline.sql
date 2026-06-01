-- subarr-telemetry baseline schema.
--
-- Privacy-by-construction: this schema is the ENFORCEMENT layer for the
-- forbidden-fields list in src/subarr/telemetry.py's
-- test_payload_never_includes_forbidden_fields. If a future client
-- accidentally sends file paths, titles, IPs, hostnames, API keys,
-- languages, etc., they have nowhere to land — the worker's INSERT
-- explicitly enumerates the allowed columns. The forbidden fields are
-- silently dropped, never written, never queryable.
--
-- Append-only with bucketing for the leaderboard work in v1.1. Raw
-- pings stay around long enough to compute 7d/30d active-install
-- counts; aggregate rollups (subgen_mix, integration_mix,
-- library_size_dist, etc.) are computed on demand from the raw table
-- for v1.0 and can be promoted to materialized rollup tables when the
-- query gets expensive enough.

CREATE TABLE IF NOT EXISTS pings (
  -- Anonymous install id from the subarr client (random UUID, generated
  -- locally on first run, persisted in subarr.db). NOT a user identity.
  install_id        TEXT NOT NULL,
  -- When the worker received the ping. Source-of-truth for "last seen".
  received_at       INTEGER NOT NULL,
  -- When the client says it sent the payload. Stored separately so we
  -- can detect clock skew or replay attempts; never trusted over received_at.
  sent_at           INTEGER,
  -- Coarse client identity. These four together pin a build but cannot
  -- pin a user.
  subarr_version    TEXT,
  python_version    TEXT,
  os_arch           TEXT,
  docker_tier       TEXT,
  -- Subgen identity. "subarr-subgen" vs "vanilla" vs "unreachable".
  subgen_kind       TEXT,
  subgen_version    TEXT,
  -- Integration booleans serialised as TEXT JSON for v1.0. Reaches a
  -- proper junction table when we add the global provider leaderboard.
  -- Shape: {"bazarr":true,"sonarr":true,"radarr":false,"tautulli":true,
  --         "plex":true,"ollama":false}
  integrations_json TEXT,
  -- Coarse buckets, never the raw count.
  library_bucket    TEXT,  -- 'under_100' | '100_1k' | '1k_10k' | 'over_10k'
  scheduler_mode    TEXT,  -- 'manual_confirm' | 'auto_queue' | 'disabled'
  walks_per_day     REAL,  -- 30d rolling avg
  -- Error breakdown by exception class. Never a stack trace, never a path.
  error_counts_json TEXT,
  -- The raw payload as the client sent it (validated against an allow-list
  -- before insert). Stored so we can debug schema migrations without
  -- needing the client to resend. Forbidden fields are stripped before
  -- this column is written.
  raw_payload_json  TEXT,
  PRIMARY KEY (install_id, received_at)
);

-- Lookup index for "active installs in the last N days" — the single
-- most-requested aggregation, drives subarr.com/stats's top number.
CREATE INDEX IF NOT EXISTS idx_pings_received_at
  ON pings (received_at);

-- Rate-limit tracking. We store the last-accepted ping per install
-- separately so we can answer "are you flooding?" in O(1) without
-- scanning the full pings table.
CREATE TABLE IF NOT EXISTS install_state (
  install_id          TEXT PRIMARY KEY,
  last_accepted_at    INTEGER NOT NULL,
  flood_warnings      INTEGER NOT NULL DEFAULT 0,
  -- Set when this install has been rejected for flooding 3+ times in
  -- a row. Subarr's Settings panel surfaces this as "Your install is
  -- pinging too often — likely a bug, please file an issue."
  flagged             INTEGER NOT NULL DEFAULT 0,
  flagged_at          INTEGER
);
