-- subarr #202: activation-funnel data-dive query pack.
--
-- Run with:
--   npx wrangler d1 execute subarr-telemetry --remote --command "<query>"
-- or:
--   npx wrangler d1 execute subarr-telemetry --remote --file docs/202-activation-funnel-queries.sql
--
-- Requires `npx wrangler login` (or CLOUDFLARE_API_TOKEN) first.
--
-- ============================================================================
-- READ THIS BEFORE INTERPRETING ANYTHING
-- ============================================================================
-- The issue frames the finding as a binary: 2,024 of ~2,036 installs report
-- library_bucket under_100, so they are EITHER short-lived trials OR the
-- onboarding funnel loses them.
--
-- There is a third possibility the issue predates, and it has to be ruled out
-- FIRST because it would invalidate the denominator rather than explain it:
--
--   INSTALL_ID CHURN. When /data is not a real mount, the container's writable
--   layer is ephemeral, so a fresh install_id is minted on every restart.
--   One user restarting 40 times looks like 40 distinct installs, each aged ~0
--   days, each having never completed a walk, each reporting under_100.
--
-- That is exactly the shape of the reported symptom. Migration 0003 added
-- install_age_days and data_persistent to test it. Query A0 runs first for
-- that reason: if a large share of installs are non-persistent, the 99.5%
-- figure is substantially a MEASUREMENT ARTEFACT and the product conclusion
-- ("we lose everyone at onboarding") would be wrong.
--
-- Only once A0 is answered do the funnel queries mean what they appear to.
-- ============================================================================


-- A0. Is the denominator real? Persistence vs install age.
-- Expect: if data_persistent=0 rows skew to age ~0, we are counting restarts.
SELECT
  data_persistent,
  COUNT(DISTINCT install_id)              AS installs,
  ROUND(AVG(install_age_days), 2)         AS avg_age_days,
  ROUND(MAX(install_age_days), 2)         AS max_age_days,
  SUM(CASE WHEN install_age_days < 1 THEN 1 ELSE 0 END) AS pings_from_installs_under_1d
FROM pings
GROUP BY data_persistent;


-- A1. Age distribution, which separates "trial" from "churned id".
-- A genuine short-lived trial still ages a few days before going quiet.
-- A churned id is ALWAYS ~0 and never grows.
SELECT
  CASE
    WHEN install_age_days IS NULL THEN 'unknown'
    WHEN install_age_days < 1  THEN '0 under_1d'
    WHEN install_age_days < 7  THEN '1 1-7d'
    WHEN install_age_days < 30 THEN '2 7-30d'
    ELSE                            '3 over_30d'
  END AS age_band,
  COUNT(DISTINCT install_id) AS installs
FROM pings
GROUP BY age_band
ORDER BY age_band;


-- B1. The headline, restricted to installs we believe are real.
-- Compare against the unrestricted number to size the artefact.
SELECT
  library_bucket,
  COUNT(DISTINCT install_id) AS installs
FROM pings
WHERE data_persistent = 1
GROUP BY library_bucket
ORDER BY installs DESC;


-- B2. Same, unrestricted, for the side-by-side.
SELECT library_bucket, COUNT(DISTINCT install_id) AS installs
FROM pings GROUP BY library_bucket ORDER BY installs DESC;


-- C1. Where in the wizard do they stop? This is the actual funnel.
-- onboarding_step is 0-11; onboarding_complete flips to 1 at the end.
SELECT
  onboarding_step,
  onboarding_complete,
  COUNT(DISTINCT install_id) AS installs
FROM pings
WHERE data_persistent = 1
GROUP BY onboarding_step, onboarding_complete
ORDER BY onboarding_step;


-- C2. Completed onboarding but still under_100 files. THE key cohort:
-- these are people the product reached and still failed to activate, which is
-- a different and more actionable problem than never finishing the wizard.
SELECT COUNT(DISTINCT install_id) AS installs
FROM pings
WHERE data_persistent = 1
  AND onboarding_complete = 1
  AND library_bucket = 'under_100';


-- D1. Do they ever walk? walks_per_day is a 30d rolling average.
SELECT
  CASE
    WHEN walks_per_day IS NULL   THEN 'unknown'
    WHEN walks_per_day = 0       THEN 'never walked'
    WHEN walks_per_day < 0.1     THEN 'under 0.1/day'
    ELSE                              'walking'
  END AS walk_band,
  COUNT(DISTINCT install_id) AS installs
FROM pings
WHERE data_persistent = 1
GROUP BY walk_band;


-- E1. Integrations configured vs not. An install with no arr configured
-- cannot produce coverage, so under_100 would be expected, not a funnel loss.
SELECT
  integrations_json,
  COUNT(DISTINCT install_id) AS installs
FROM pings
WHERE data_persistent = 1
GROUP BY integrations_json
ORDER BY installs DESC
LIMIT 15;


-- F1. Longevity: do installs come back? Repeat pings per install.
SELECT
  CASE
    WHEN n = 1        THEN '1 ping only'
    WHEN n < 7        THEN '2-6 pings'
    WHEN n < 30       THEN '7-29 pings'
    ELSE                   '30+ pings'
  END AS ping_band,
  COUNT(*) AS installs
FROM (
  SELECT install_id, COUNT(*) AS n
  FROM pings
  WHERE data_persistent = 1
  GROUP BY install_id
)
GROUP BY ping_band;
