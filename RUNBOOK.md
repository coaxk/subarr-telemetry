# Operations runbook — telemetry.subarr.com + stats.subarr.com

Everything an operator needs to deploy, migrate, debug, and recover this
stack without the maintainer's memory. Companion to `README.md` (what the
service does) — this file is *how to run it*.

## Topology

| Piece | Where | What |
|---|---|---|
| Receiver worker | CF Workers, `subarr-telemetry` | `telemetry.subarr.com/v1/ping` + read-only `/v1/stats/*` |
| Database | CF D1, `subarr-telemetry` | `pings`, `crashes`, `install_state` + `d1_migrations` ledger |
| Dashboard | CF Pages | `stats.subarr.com` (static `stats/index.html`, reads the worker's stats endpoints) |
| CI | `.github/workflows/ci.yml` | vitest (incl. corpus replay) → migrate → deploy on main |

## Local environment gotchas (Windows host)

- **wrangler needs Node 22**: `nvm use 22.22.3` first. Older Node fails in
  non-obvious ways.
- **`$env:CI = "true"` before any wrangler D1 command.** Without it, wrangler
  asks an interactive yes/no that hangs forever in non-interactive shells
  (this orphaned two background shells for 11+ hours on 2026-06-11).
- Account auth: `wrangler whoami` to confirm; `wrangler login` if not.

## Deploy

**Order is law: migrate BEFORE deploy.** The worker code assumes the schema
its migrations describe; deploying first opens a window where inserts hit
missing columns and pings 500.

```powershell
nvm use 22.22.3
$env:CI = "true"
npx wrangler d1 migrations apply subarr-telemetry --remote
npx wrangler deploy
```

CI does the same on every push to main (`ci.yml`: test → migrate → deploy).
The deploy job needs the `CLOUDFLARE_API_TOKEN` repo secret — verify with
`gh secret list` and **watch a real green run of the deploy job**, not just
tests ("it's in CI" ≠ "CI does it"; this job sat dead with an empty token
for weeks once).

## Migrations

- Files live in `migrations/NNNN_name.sql`, applied in filename order;
  applied ones are recorded in the `d1_migrations` table.
- Add a migration: create the next-numbered file, never edit an applied one.
- Check state: `npx wrangler d1 migrations list subarr-telemetry --remote`
- Schema changes must stay in lockstep with `ALLOWED_FIELDS` /
  `STATS_COLUMNS` in `src/worker.js` and with subarr's
  `tests/test_telemetry.py` forbidden-fields regression test.

## Verify after deploy

```powershell
# Receiver up?
Invoke-RestMethod https://telemetry.subarr.com/v1/stats/versions
# Send a synthetic ping (fake install_id) and confirm the counter moves:
Invoke-RestMethod -Method POST https://telemetry.subarr.com/v1/ping `
  -ContentType application/json `
  -Body '{"install_id":"00000000000000000000000000000000","subarr_version":"0.0.0-synthetic"}'
```

Then check the version distribution again — `0.0.0-synthetic` should appear
within the stats cache TTL (300s edge cache on `/v1/stats/*`).

**Verify against REAL payloads, not hand-written ones.** The 2026-06-09
fleet-wide outage (~99.5% of pings rejected for 3 days) was a validator
change that passed every synthetic test and failed on what real installs
actually send. `test/corpus/real-pings.json` holds 60 verbatim production
payloads; the corpus replay test in CI replays them all. When touching
validation, add current production payloads to the corpus first.

## Debugging a ping outage

1. **Is the fleet flat or is one install flat?** stats dashboard → 7d view.
   Fleet-flat = server-side (validator/schema/deploy); single = client-side.
2. Tail live: `npx wrangler tail subarr-telemetry` and watch real inbound
   pings get accepted/rejected with reasons.
3. Reproduce with a captured payload from the corpus, not a synthetic one.
4. Check `d1_migrations` state matches what the deployed worker expects.

## D1 restore (Time Travel)

D1 keeps 30 days of point-in-time history. To restore:

```powershell
# Find the database id
npx wrangler d1 info subarr-telemetry
# List restore points / restore to a timestamp (UTC)
npx wrangler d1 time-travel info subarr-telemetry
npx wrangler d1 time-travel restore subarr-telemetry --timestamp=2026-06-01T00:00:00Z
```

Restoring rewinds the WHOLE database including `d1_migrations` — after a
restore, re-run `migrations apply` to roll forward any migrations newer
than the restore point, THEN redeploy the worker.

## Custom domains

- `telemetry.subarr.com`: Workers & Pages → subarr-telemetry → Settings →
  Triggers → Custom Domains. DNS auto-created (subarr.com is on CF).
- `stats.subarr.com`: the Pages project's custom domain, same dashboard.

## Caching

`/v1/stats/*` GET responses are edge-cached 300s (`STATS_CACHE_TTL_S`,
Cache API in `src/worker.js`). A "stale" dashboard within 5 minutes of a
change is the cache, not a bug. `/v1/ping` is never cached.

## Data policy quick-reference

- Privacy: hard column allow-list; forbidden fingerprintable fields reject
  the whole payload with 400 (see README for the table).
- Unknown-but-allowed fields are dropped per-field, not rejected — a newer
  subarr pinging an older worker must not lose the whole ping.
- Rate limits: 1 ping/hour per install_id; <60s apart = flood detection
  (3 strikes → flagged). Synthetic-test pings should use a throwaway
  install_id to avoid flagging a real one.
