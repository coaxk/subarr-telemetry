-- subarr #479: subgen reachability, cause-bucketed. Re-runnable.
--
--   $env:CI = "true"
--   npx wrangler d1 execute subarr-telemetry --remote --file docs/479-subgen-reachability-queries.sql
--
-- Population: GENUINE installs (worker.js GENUINE_INSTALLS_SQL, verbatim),
-- latest ping per install in the last 30 days, restricted to pings that CARRY
-- the migration-0005 fields (subgen_target_is_default IS NOT NULL), i.e.
-- clients on 2.6.0+. Earlier clients cannot say why a probe failed and are
-- excluded rather than folded into a bucket they cannot fill.
--
-- "walking, real library" = walks_per_day > 0 AND library_bucket <> 'under_100',
-- matching the 2026-08-31 comment on #479 so the tables compare directly.

-- Q0. Sample size and version mix of the carrying set (bias check).
WITH genuine AS (
  SELECT install_id FROM pings
  GROUP BY install_id
  HAVING MAX(COALESCE(data_persistent, 0)) = 1
      OR COUNT(DISTINCT CAST(received_at / 86400 AS INTEGER)) >= 2
),
latest AS (
  SELECT p.* FROM pings p
  JOIN (
    SELECT install_id, MAX(received_at) AS r FROM pings
    WHERE received_at > strftime('%s', 'now') - 30 * 86400
    GROUP BY install_id
  ) m ON m.install_id = p.install_id AND m.r = p.received_at
  WHERE p.install_id IN (SELECT install_id FROM genuine)
)
SELECT
  (SELECT COUNT(*) FROM latest) AS genuine_30d,
  (SELECT COUNT(*) FROM latest WHERE subgen_target_is_default IS NOT NULL) AS carrying_new_fields,
  (SELECT GROUP_CONCAT(v, ', ') FROM (
     SELECT subarr_version || ' x' || COUNT(*) AS v FROM latest
     WHERE subgen_target_is_default IS NOT NULL
     GROUP BY subarr_version ORDER BY COUNT(*) DESC)) AS versions_in_carrying_set;

-- Q1. Cause breakdown x whether the install is still on the shipped SUBGEN_URL.
WITH genuine AS (
  SELECT install_id FROM pings
  GROUP BY install_id
  HAVING MAX(COALESCE(data_persistent, 0)) = 1
      OR COUNT(DISTINCT CAST(received_at / 86400 AS INTEGER)) >= 2
),
latest AS (
  SELECT p.* FROM pings p
  JOIN (
    SELECT install_id, MAX(received_at) AS r FROM pings
    WHERE received_at > strftime('%s', 'now') - 30 * 86400
    GROUP BY install_id
  ) m ON m.install_id = p.install_id AND m.r = p.received_at
  WHERE p.install_id IN (SELECT install_id FROM genuine)
)
SELECT
  CASE WHEN subgen_kind = 'unreachable' THEN COALESCE(subgen_probe_failure, 'unreachable_no_cause')
       ELSE 'reachable' END AS probe_result,
  CASE WHEN subgen_target_is_default = 1 THEN 'default' ELSE 'configured' END AS target,
  COUNT(*) AS installs
FROM latest
WHERE subgen_target_is_default IS NOT NULL
GROUP BY 1, 2
ORDER BY installs DESC;

-- Q2. Reachability x actual use.
WITH genuine AS (
  SELECT install_id FROM pings
  GROUP BY install_id
  HAVING MAX(COALESCE(data_persistent, 0)) = 1
      OR COUNT(DISTINCT CAST(received_at / 86400 AS INTEGER)) >= 2
),
latest AS (
  SELECT p.* FROM pings p
  JOIN (
    SELECT install_id, MAX(received_at) AS r FROM pings
    WHERE received_at > strftime('%s', 'now') - 30 * 86400
    GROUP BY install_id
  ) m ON m.install_id = p.install_id AND m.r = p.received_at
  WHERE p.install_id IN (SELECT install_id FROM genuine)
)
SELECT
  CASE WHEN subgen_kind = 'unreachable' THEN 'unreachable' ELSE 'reachable' END AS state,
  CASE WHEN subgen_target_is_default = 1 THEN 'default' ELSE 'configured' END AS target,
  SUM(CASE WHEN COALESCE(walks_per_day, 0) > 0 AND library_bucket <> 'under_100' THEN 1 ELSE 0 END) AS walking_real_lib,
  SUM(CASE WHEN COALESCE(walks_per_day, 0) > 0 AND library_bucket = 'under_100' THEN 1 ELSE 0 END) AS walking_small_lib,
  SUM(CASE WHEN COALESCE(walks_per_day, 0) = 0 THEN 1 ELSE 0 END) AS never_walked,
  COUNT(*) AS total
FROM latest
WHERE subgen_target_is_default IS NOT NULL
GROUP BY 1, 2
ORDER BY 1, 2;

-- Q3. The one cell that is unambiguously the bug: configured, unreachable,
-- and walking a real library. Cause for each.
WITH genuine AS (
  SELECT install_id FROM pings
  GROUP BY install_id
  HAVING MAX(COALESCE(data_persistent, 0)) = 1
      OR COUNT(DISTINCT CAST(received_at / 86400 AS INTEGER)) >= 2
),
latest AS (
  SELECT p.* FROM pings p
  JOIN (
    SELECT install_id, MAX(received_at) AS r FROM pings
    WHERE received_at > strftime('%s', 'now') - 30 * 86400
    GROUP BY install_id
  ) m ON m.install_id = p.install_id AND m.r = p.received_at
  WHERE p.install_id IN (SELECT install_id FROM genuine)
)
SELECT COALESCE(subgen_probe_failure, 'unreachable_no_cause') AS cause,
       subarr_version, library_bucket, ROUND(walks_per_day, 2) AS walks_per_day,
       ROUND(install_age_days, 0) AS age_days
FROM latest
WHERE subgen_target_is_default = 0
  AND subgen_kind = 'unreachable'
  AND COALESCE(walks_per_day, 0) > 0
ORDER BY age_days DESC;
