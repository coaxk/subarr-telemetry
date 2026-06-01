# subarr.com/stats — public stats page

Static single-page dashboard that hits the worker's `/v1/stats/*` endpoints on `telemetry.subarr.com` and renders the aggregate numbers. Refreshes every 60s.

Lives in this repo (not the main subarr repo) because it's pure consumer of the worker and ships independently — no Python, no Docker, no build step.

## What's on the page

- **Receiver status** — green dot if `telemetry.subarr.com/v1/health` returns `{ok:true}`.
- **Active installs** — last 7d / 30d / total ever, from `/v1/stats/installs`.
- **Subgen mix** — % subarr-subgen vs vanilla vs unreachable, from `/v1/stats/subgen-mix`.
- **Integration adoption** — per-integration usage %, from `/v1/stats/integrations`.

Library-size distribution, scheduler-mode mix, walks-per-day histogram, and the global provider success leaderboard all have worker endpoints already; their frontend cards land in v1.1.

## What's NOT on the page (and why it can't be)

Paths, titles, IPs, hostnames, API keys, languages, anything user-fingerprintable. The receiving worker rejects payloads containing any of them with HTTP 400. The database has no columns to store them. The page can only show what's in the columns, which is the allow-list defined in `../src/worker.js`.

## Deploy

**Option 1 — Cloudflare Pages (recommended, free, ~5 min):**

1. Cloudflare dashboard → Workers & Pages → Create application → Pages
2. Connect to GitHub → `coaxk/subarr-telemetry`
3. Build settings:
   - Build command: *(none)*
   - Build output directory: `stats`
   - Root directory: *(leave blank)*
4. Save and Deploy. First deploy gives you `subarr-telemetry-stats.pages.dev`.
5. Custom domain: Pages project → Custom domains → Set up → `subarr.com/stats`
   - If `subarr.com` is on Cloudflare DNS the record auto-creates.
   - Note this is a **subdirectory** custom domain — Cloudflare supports `subarr.com/stats` via Pages by routing the path on the apex domain.

**Option 2 — GitHub Pages from this dir:**

1. Repo settings → Pages → Source: deploy from a branch → `main` / `/stats`
2. Add CNAME file in `stats/CNAME` containing `subarr.com` (apex) — would conflict with telemetry subdomain DNS so this option only works if `subarr.com` apex is fully GitHub Pages, which it likely isn't.

**Option 3 — Host on the worker itself:**

The worker can serve the static page if we add a `GET /stats` handler that returns the HTML body. Slightly heavier — every page load hits the worker — but no separate deploy. Skipping for v1.0; revisit if Pages becomes inconvenient.

Pick option 1.

## Local preview

Open `index.html` directly in a browser. The fetch calls hit the live `telemetry.subarr.com` so the numbers will reflect actual production data.

## Maintenance

The page is intentionally ~250 lines of inline CSS + 60 lines of JS with no dependencies. If we need a chart library later (Recharts, Chart.js) the migration target is a real React app — but for the v1.0 single-numbers-per-row view, vanilla wins.
