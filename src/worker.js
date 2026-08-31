// subarr-telemetry — Cloudflare Worker.
//
// Routes:
//   POST /v1/ping                     — receive a heartbeat from a subarr install
//   GET  /v1/stats/installs           — active installs in last 7d / 30d
//   GET  /v1/stats/subgen-mix         — % running subarr-subgen vs vanilla vs unreachable
//   GET  /v1/stats/integrations       — per-integration usage %
//   GET  /v1/stats/library-size       — distribution across library buckets
//   GET  /v1/stats/walks-per-day      — distribution across cadence buckets
//   GET  /v1/stats/scheduler-modes    — manual_confirm vs auto_queue vs disabled
//   GET  /v1/stats/versions           — subarr version distribution (30d window)
//   GET  /v1/stats/versions-7d        — same, 7d window (release-rollout watching)
//   GET  /v1/health                   — worker liveness (no DB hit)
//
// All POSTs respect a per-install rate limit (env.MIN_INTERVAL_S). Pings
// arriving sooner than that get rejected with 429. Pings arriving sooner
// than env.FLOOD_THRESHOLD_S are flagged in the response payload so the
// in-product Settings panel can show "Your install is pinging too often"
// to the user. After 3 consecutive flood rejections, the install_id is
// flagged for permanent attention in the install_state table.

// Allow-list of payload fields that may be persisted. Anything else in
// the inbound JSON is silently dropped. Mirrors src/subarr/telemetry.py
// TelemetryPayload.to_dict() exactly. If you add a field there, add it
// here. The regression test in test/worker.test.js enforces that
// forbidden fields from the subarr regression test get dropped, NOT just
// stored under a different name.
const ALLOWED_FIELDS = new Set([
  "install_id",
  "sent_at",
  "subarr_version",
  "python_version",
  "os_arch",
  "docker_tier",
  "subgen_kind",
  "subgen_version",
  "integrations",          // object, normalised into integrations_json
  "library_bucket",
  "scheduler_mode",
  "scheduler_enabled",     // legacy field, accepted but not persisted (covered by scheduler_mode)
  "walks_per_day_30d",
  "error_counts_30d",      // object, normalised into error_counts_json
  "crash_counts_24h",      // #157 P2: object {ExcType:module:line -> count}, normalised into crashes_json
  "install_age_days",      // retention signal: days since this install_id was created
  "data_persistent",       // bool: is /data a real mount vs the container's ephemeral layer
  "onboarding_step",       // #202: coarse furthest onboarding step reached (0-11)
  "onboarding_complete",   // #202: bool — did they finish the wizard
  // #479: split the `unreachable` bucket. Neither can carry a hostname,
  // URL, port or exception text.
  "subgen_probe_failure",     // closed vocabulary, NULL when reachable
  "subgen_target_is_default", // still on the shipped SUBGEN_URL
]);

// Forbidden families. If any incoming key matches one of these patterns,
// reject the entire payload — this signals a buggy client, not a stray
// field. Keep in sync with subarr's regression test forbidden list.
const FORBIDDEN_PATTERNS = [
  /^path$/i, /paths?$/i,
  /^title$/i,
  /^api[_-]?key/i, /^token/i, /^password/i, /^secret/i,
  /^ip$/i, /^ip[_-]?address/i, /^hostname/i, /^host$/i, /^url$/i,
  /^language/i, /^lang$/i,
  /^email/i, /^username$/i, /^user[_-]?name/i,
];

// Value-level validation (defense in depth). The key-name allow/deny lists
// above don't constrain VALUES — without this, an attacker can store markup
// (stored XSS on the public stats page via rendered bucket labels), smuggle a
// secret into an allowed field, or stuff 8KB of junk into a GROUP BY column.
const MAX_STR = 64;                         // generous for versions/arch/buckets
const XSS_CHARS = /[<>"'`]/;                // never legitimately in these fields
const SECRET_SIG = /sk-[A-Za-z0-9]{12}|xox[baprs]-|Bearer\s|-----BEGIN|[A-Fa-f0-9]{32,}|[A-Za-z0-9+/]{40,}={0,2}/;
// String fields that get persisted (and several rendered on stats.subarr.com).
// library_bucket is NOT in this list: subarr has always sent the literals
// "<100" and ">10k", whose angle brackets trip XSS_CHARS — the 06-08
// hardening silently 400-rejected ~99.5% of the fleet on exactly that
// (every install that never ran a probe walk reports "<100"). It gets an
// exact-match allowlist instead (see validatePayload), which is BOTH safer
// (no arbitrary string ever stored/rendered) and compatible.
const VALIDATED_STRINGS = [
  "subarr_version", "python_version", "os_arch", "docker_tier",
  "subgen_kind", "subgen_version", "scheduler_mode",
];

// The bucket literals every shipped subarr version emits. An unknown value
// drops the FIELD (stored as null), never the ping — field-level violations
// on non-critical display fields must not cost us the whole fleet again.
// Both families: the angle/hyphen literals real clients send (verified in
// D1: "<100" alone = ~99.5% of the fleet) AND the underscore variants the
// original worker spec imagined — harmless to accept, and the old tests pin
// them.
const LIBRARY_BUCKETS = new Set([
  "<100", "100-1k", "1k-10k", ">10k", "unknown",
  "under_100", "100_1k", "1k_10k", "over_10k",
]);

function badStringValue(name, val) {
  if (typeof val !== "string") return `${name} must be a string`;
  if (val.length > MAX_STR) return `${name} too long`;
  if (XSS_CHARS.test(val)) return `${name} contains invalid characters`;
  if (SECRET_SIG.test(val)) return `${name} looks like it contains a secret`;
  return null;
}

function corsHeaders(env, origin) {
  const allowed = (env.ALLOWED_ORIGINS || "").split(",").map(s => s.trim());
  const allow = (origin && allowed.includes(origin)) ? origin : allowed[0] || "*";
  return {
    "Access-Control-Allow-Origin": allow,
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Max-Age": "86400",
  };
}

function jsonResponse(body, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
      ...extraHeaders,
    },
  });
}

// Parse + validate the inbound payload. Returns { ok, value, reason }.
// Forbidden keys → ok:false. Unknown allowed keys → silently dropped.
// All allowed keys → ok:true with a normalised object.
export function validatePayload(raw) {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    return { ok: false, reason: "payload must be a JSON object" };
  }
  const keys = Object.keys(raw);
  for (const k of keys) {
    if (FORBIDDEN_PATTERNS.some(p => p.test(k))) {
      return { ok: false, reason: `forbidden field: ${k}` };
    }
  }
  const out = {};
  for (const k of keys) {
    if (ALLOWED_FIELDS.has(k)) out[k] = raw[k];
  }
  if (typeof out.install_id !== "string" || out.install_id.length < 8) {
    return { ok: false, reason: "install_id missing or too short" };
  }
  // Reject install_id that looks like an email/hostname/path — defense
  // in depth against a buggy client putting PII in the ID field.
  if (/[@/.]/.test(out.install_id) && out.install_id.length < 32) {
    return { ok: false, reason: "install_id looks fingerprintable" };
  }

  // subarr (≤1.4.0) sends docker_tier as a NUMBER (1|2|3). The 2026-06-08
  // value-validation hardening required a string here and silently
  // 400-rejected every real ping fleet-wide for 3 days. Deployed clients
  // can't be retro-fixed → coerce finite numbers to their string form.
  // Pinned by the verbatim-1.4.0-payload regression test.
  if (typeof out.docker_tier === "number" && Number.isFinite(out.docker_tier)) {
    out.docker_tier = String(out.docker_tier);
  }

  // --- Value-level validation (defense in depth) ---
  // The allow/deny lists above only gate KEY names. Without this, a crafted
  // value can (a) become stored XSS on the public stats page via a rendered
  // bucket label, (b) smuggle a secret into an allowed field, or (c) flood a
  // GROUP BY column. Reject the whole ping on any violation — a legit client
  // never sends markup, secrets, or oversize strings in these fields.
  for (const f of VALIDATED_STRINGS) {
    if (out[f] == null) continue;
    const bad = badStringValue(f, out[f]);
    if (bad) return { ok: false, reason: bad };
  }
  // library_bucket: exact-match allowlist (see LIBRARY_BUCKETS comment).
  // Unknown/invalid values drop the field, not the ping.
  if (out.library_bucket != null && !LIBRARY_BUCKETS.has(out.library_bucket)) {
    out.library_bucket = null;
  }
  if (out.walks_per_day_30d != null) {
    const n = out.walks_per_day_30d;
    if (typeof n !== "number" || !Number.isFinite(n) || n < 0 || n > 100000) {
      return { ok: false, reason: "walks_per_day_30d out of range" };
    }
  }
  // install_age_days / data_persistent: non-critical signals — an invalid
  // value DROPS THE FIELD, never the ping (the library_bucket lesson:
  // a display/analytics field must not cost us the whole fleet).
  if (out.install_age_days != null) {
    const n = out.install_age_days;
    if (typeof n !== "number" || !Number.isFinite(n) || n < 0 || n > 100000) {
      out.install_age_days = null;
    }
  }
  if (out.data_persistent != null && typeof out.data_persistent !== "boolean") {
    out.data_persistent = null;
  }
  // #202 onboarding funnel: coarse non-critical signals — invalid values DROP
  // THE FIELD, never the ping.
  if (out.onboarding_step != null) {
    const n = out.onboarding_step;
    if (typeof n !== "number" || !Number.isInteger(n) || n < 0 || n > 99) {
      out.onboarding_step = null;
    }
  }
  if (out.onboarding_complete != null && typeof out.onboarding_complete !== "boolean") {
    out.onboarding_complete = null;
  }
  // integrations + error_counts_30d + crash_counts_24h are flat objects whose
  // KEYS are rendered on the stats page → same XSS/secret/length rules;
  // values must be simple.
  for (const f of ["integrations", "error_counts_30d", "crash_counts_24h"]) {
    const o = out[f];
    if (o == null) continue;
    if (typeof o !== "object" || Array.isArray(o)) {
      return { ok: false, reason: `${f} must be an object` };
    }
    const entries = Object.entries(o);
    if (entries.length > 64) return { ok: false, reason: `${f} has too many keys` };
    for (const [k, v] of entries) {
      const bad = badStringValue(`${f} key`, k);
      if (bad) return { ok: false, reason: bad };
      if (typeof v !== "boolean" && typeof v !== "number") {
        return { ok: false, reason: `${f}.${k} must be a boolean or number` };
      }
      if (typeof v === "number" && (!Number.isFinite(v) || Math.abs(v) > 1e9)) {
        return { ok: false, reason: `${f}.${k} out of range` };
      }
    }
  }

  return { ok: true, value: out };
}

// Look up the install's last-accepted timestamp and decide whether
// this new ping should be accepted, rate-limited, or marked as flood.
async function checkRateLimit(env, installId, nowS) {
  const minInterval = parseInt(env.MIN_INTERVAL_S || "3600", 10);
  const floodThreshold = parseInt(env.FLOOD_THRESHOLD_S || "60", 10);
  const row = await env.DB.prepare(
    "SELECT last_accepted_at, flood_warnings, flagged FROM install_state WHERE install_id = ?"
  ).bind(installId).first();
  if (!row) return { decision: "accept", flood: false, sinceLastS: null };
  const sinceLastS = nowS - row.last_accepted_at;
  if (sinceLastS < floodThreshold) {
    return { decision: "reject_flood", flood: true, sinceLastS, retryAfterS: minInterval - sinceLastS };
  }
  if (sinceLastS < minInterval) {
    return { decision: "reject_rate_limit", flood: false, sinceLastS, retryAfterS: minInterval - sinceLastS };
  }
  return { decision: "accept", flood: false, sinceLastS };
}

async function recordPing(env, payload, nowS) {
  // Idempotent install_state update — accept the latest ping, bump
  // flood_warnings if applicable, and clear them on any acceptance.
  const integrationsJson = payload.integrations ? JSON.stringify(payload.integrations) : null;
  const errorCountsJson = payload.error_counts_30d ? JSON.stringify(payload.error_counts_30d) : null;
  const crashesJson = payload.crash_counts_24h ? JSON.stringify(payload.crash_counts_24h) : null;
  const rawPayloadJson = JSON.stringify(payload);
  await env.DB.batch([
    env.DB.prepare(
      `INSERT INTO pings (
         install_id, received_at, sent_at,
         subarr_version, python_version, os_arch, docker_tier,
         subgen_kind, subgen_version,
         integrations_json, library_bucket, scheduler_mode,
         walks_per_day, error_counts_json, crashes_json,
         install_age_days, data_persistent,
         onboarding_step, onboarding_complete,
         subgen_probe_failure, subgen_target_is_default,
         raw_payload_json
       ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
    ).bind(
      payload.install_id, nowS, payload.sent_at ?? null,
      payload.subarr_version ?? null, payload.python_version ?? null,
      payload.os_arch ?? null, payload.docker_tier ?? null,
      payload.subgen_kind ?? null, payload.subgen_version ?? null,
      integrationsJson, payload.library_bucket ?? null,
      payload.scheduler_mode ?? null,
      payload.walks_per_day_30d ?? null,
      errorCountsJson, crashesJson,
      payload.install_age_days ?? null,
      payload.data_persistent == null ? null : (payload.data_persistent ? 1 : 0),
      payload.onboarding_step ?? null,
      payload.onboarding_complete == null ? null : (payload.onboarding_complete ? 1 : 0),
      payload.subgen_probe_failure ?? null,
      payload.subgen_target_is_default == null
        ? null
        : (payload.subgen_target_is_default ? 1 : 0),
      rawPayloadJson,
    ),
    env.DB.prepare(
      `INSERT INTO install_state (install_id, last_accepted_at, flood_warnings, flagged)
       VALUES (?, ?, 0, 0)
       ON CONFLICT(install_id) DO UPDATE SET
         last_accepted_at = excluded.last_accepted_at,
         flood_warnings = 0`
    ).bind(payload.install_id, nowS),
  ]);
}

async function recordFlood(env, installId, nowS) {
  // Bump flood_warnings; flag after 3 consecutive. Each acceptance
  // resets the counter to 0 (see recordPing).
  await env.DB.prepare(
    `INSERT INTO install_state (install_id, last_accepted_at, flood_warnings, flagged, flagged_at)
     VALUES (?, ?, 1, 0, NULL)
     ON CONFLICT(install_id) DO UPDATE SET
       flood_warnings = install_state.flood_warnings + 1,
       flagged    = CASE WHEN install_state.flood_warnings + 1 >= 3 THEN 1 ELSE install_state.flagged END,
       flagged_at = CASE WHEN install_state.flood_warnings + 1 >= 3 AND install_state.flagged_at IS NULL THEN ? ELSE install_state.flagged_at END`
  ).bind(installId, nowS, nowS).run();
}

async function handlePing(request, env, nowS) {
  // Per-IP edge throttle FIRST — before reading the body or touching D1 — so a
  // flood is shed at the cheapest possible point. Keyed on CF-Connecting-IP,
  // which the limiter uses transiently and never persists (no PII stored).
  // Optional-chained so local/test envs without the binding still run.
  if (env.PING_LIMITER) {
    const ip = request.headers.get("CF-Connecting-IP") || "unknown";
    const { success } = await env.PING_LIMITER.limit({ key: ip });
    if (!success) {
      return jsonResponse({ ok: false, reason: "rate_limited" }, 429, { "Retry-After": "60" });
    }
  }
  const maxBytes = parseInt(env.MAX_PAYLOAD_BYTES || "8192", 10);
  const text = await request.text();
  if (text.length > maxBytes) {
    return jsonResponse({ ok: false, reason: "payload too large" }, 413);
  }
  let raw;
  try { raw = JSON.parse(text); }
  catch { return jsonResponse({ ok: false, reason: "invalid json" }, 400); }
  const v = validatePayload(raw);
  if (!v.ok) return jsonResponse({ ok: false, reason: v.reason }, 400);
  const rate = await checkRateLimit(env, v.value.install_id, nowS);
  if (rate.decision === "accept") {
    await recordPing(env, v.value, nowS);
    return jsonResponse({ ok: true, received_at: nowS });
  }
  if (rate.decision === "reject_flood") {
    await recordFlood(env, v.value.install_id, nowS);
    return jsonResponse({
      ok: false,
      reason: "flooding",
      flood_detected: true,
      retry_after_s: rate.retryAfterS,
      since_last_s: rate.sinceLastS,
      // Subarr's Settings panel surfaces this string verbatim.
      user_message: "Your install is sending telemetry pings much more often than expected. This is almost always a bug. Please file an issue at github.com/coaxk/subarr/issues with your subarr version.",
    }, 429, { "Retry-After": String(rate.retryAfterS) });
  }
  // Plain rate-limit. Not a bug, just too soon — daily-cadence client
  // restarted mid-day. Quiet 429, no user-facing alarm.
  return jsonResponse({
    ok: false,
    reason: "rate_limited",
    retry_after_s: rate.retryAfterS,
    since_last_s: rate.sinceLastS,
  }, 429, { "Retry-After": String(rate.retryAfterS) });
}

// ─── Aggregation endpoints ──────────────────────────────────────────

// A "genuine" install: one we have positive evidence is a real installation
// rather than a fresh install_id minted by a container whose /data was never
// a real mount (subarr #473).
//
// Why this exists. Until #473 was found, every count here was
// COUNT(DISTINCT install_id) over raw pings. An install that loses its
// database on each recreate mints a new id every time, so one user restarting
// 40 times read as 40 installs. Measured 2026-08-31: 22,840 of 23,426 distinct
// ids had never sent a second ping, averaging 1.04 pings each, against 16.5
// for ids that report a persistent /data. The published "17,417 active
// installs" was roughly 80x the truth.
//
// It distorted SHAPE, not just scale, which is the part that made it
// dangerous. The version chart showed 1.5.2 at 6,967 and 2.5.0 at 163,
// implying nobody upgrades. Filtered, it is 2.5.0 at 134 and 1.5.2 at 1: the
// ancient versions are precisely the ones whose README told people to mount
// /config, so they churn ids forever while current versions persist and count
// once. The chart was reporting the opposite of the truth.
//
// Two independent signals, OR'd, because neither alone is sufficient:
//
//   data_persistent = 1
//       The client checked its own /data and reported a real mount. Only
//       clients from the migration-0003 era onward send it at all, so on its
//       own it silently discards every genuine install on an older client.
//
//   seen on >= 2 distinct UTC days
//       Recurrence. Client-version independent, so it rescues the old-client
//       installs the flag cannot see (60 of them at time of writing). On its
//       own it would exclude genuine installs that arrived today and have only
//       pinged once, which is why the flag is kept alongside it.
//
// ⚠️ This is EVIDENCE OF GENUINE, not proof of the negative. An install
// excluded here is one we cannot yet vouch for, not one proven fake. A real
// install that arrived today on an old client is excluded until its second
// day. The bias is deliberately toward undercounting: a public number that is
// too low is a smaller lie than one that is 80x too high.
export const GENUINE_INSTALLS_SQL = `
  SELECT install_id FROM pings
  GROUP BY install_id
  HAVING MAX(COALESCE(data_persistent, 0)) = 1
      OR COUNT(DISTINCT CAST(received_at / 86400 AS INTEGER)) >= 2
`;


// Active installs in the last N days.
//
// active_* / total_ever count GENUINE installs (see GENUINE_INSTALLS_SQL).
// The unfiltered numbers are still published as raw_*, because they are what
// this endpoint returned before 2026-08-31 and dropping them silently would
// make the historical series unexplainable. They are not the headline: raw
// counts distinct install_ids, and a churning install mints a new one on every
// restart.
async function statsInstalls(env, nowS) {
  const day = 86400;
  const [d7, d30, total, raw7, raw30, rawTotal] = await Promise.all([
    env.DB.prepare(
      `SELECT COUNT(DISTINCT install_id) AS n FROM pings
       WHERE received_at > ? AND install_id IN (${GENUINE_INSTALLS_SQL})`
    ).bind(nowS - 7 * day).first(),
    env.DB.prepare(
      `SELECT COUNT(DISTINCT install_id) AS n FROM pings
       WHERE received_at > ? AND install_id IN (${GENUINE_INSTALLS_SQL})`
    ).bind(nowS - 30 * day).first(),
    env.DB.prepare(
      `SELECT COUNT(*) AS n FROM (${GENUINE_INSTALLS_SQL})`
    ).first(),
    env.DB.prepare("SELECT COUNT(DISTINCT install_id) AS n FROM pings WHERE received_at > ?")
      .bind(nowS - 7 * day).first(),
    env.DB.prepare("SELECT COUNT(DISTINCT install_id) AS n FROM pings WHERE received_at > ?")
      .bind(nowS - 30 * day).first(),
    env.DB.prepare("SELECT COUNT(DISTINCT install_id) AS n FROM pings").first(),
  ]);
  return jsonResponse({
    active_7d: d7?.n ?? 0,
    active_30d: d30?.n ?? 0,
    total_ever: total?.n ?? 0,
    raw_active_7d: raw7?.n ?? 0,
    raw_active_30d: raw30?.n ?? 0,
    raw_total_ever: rawTotal?.n ?? 0,
    counting: "genuine",
    counting_note:
      "Genuine = reported a persistent /data, or seen on 2+ distinct days. " +
      "raw_* counts every distinct install_id, which subarr#473 inflates " +
      "because an install with an ephemeral /data mints a new id per restart.",
    computed_at: nowS,
  });
}

// Latest known subgen_kind per install, then bucketed. We use the
// MAX(received_at) row to avoid double-counting installs that flipped
// from vanilla → subarr-subgen mid-window.
async function statsSubgenMix(env, nowS) {
  const cutoff = nowS - 30 * 86400;
  const rows = await env.DB.prepare(
    `SELECT subgen_kind, COUNT(*) AS n FROM (
       SELECT install_id, subgen_kind FROM pings p
       WHERE received_at > ?
         AND received_at = (SELECT MAX(received_at) FROM pings WHERE install_id = p.install_id)
         AND p.install_id IN (${GENUINE_INSTALLS_SQL})
     ) GROUP BY subgen_kind`
  ).bind(cutoff).all();
  return jsonResponse({
    window_days: 30,
    by_kind: rows.results || [],
    computed_at: nowS,
  });
}

async function statsIntegrations(env, nowS) {
  // Pull each install's latest integrations_json, parse, count true-counts.
  const cutoff = nowS - 30 * 86400;
  const rows = await env.DB.prepare(
    `SELECT integrations_json FROM pings p
     WHERE received_at > ?
       AND received_at = (SELECT MAX(received_at) FROM pings WHERE install_id = p.install_id)
       AND p.install_id IN (${GENUINE_INSTALLS_SQL})
       AND integrations_json IS NOT NULL`
  ).bind(cutoff).all();
  const counts = {};
  let totalInstalls = 0;
  for (const row of rows.results || []) {
    let obj;
    try { obj = JSON.parse(row.integrations_json); }
    catch { continue; }
    totalInstalls += 1;
    for (const [k, v] of Object.entries(obj || {})) {
      if (v === true) counts[k] = (counts[k] || 0) + 1;
    }
  }
  return jsonResponse({
    window_days: 30,
    total_installs: totalInstalls,
    counts,
    computed_at: nowS,
  });
}

// Columns that statsByColumn is allowed to GROUP BY. The callers below only
// ever pass hardcoded literals, so this is defensive — but `column` is
// string-interpolated into SQL (D1 can't bind identifiers), so an allowlist is
// the guardrail that keeps a future caller from turning this into injection.
const STATS_COLUMNS = new Set(["library_bucket", "walks_per_day", "scheduler_mode", "subarr_version"]);

async function statsByColumn(env, nowS, column, windowDays = 30) {
  if (!STATS_COLUMNS.has(column)) {
    return jsonResponse({ error: "unknown stats column" }, 400);
  }
  const cutoff = nowS - windowDays * 86400;
  const rows = await env.DB.prepare(
    `SELECT ${column} AS bucket, COUNT(*) AS n FROM (
       SELECT install_id, ${column} FROM pings p
       WHERE received_at > ?
         AND received_at = (SELECT MAX(received_at) FROM pings WHERE install_id = p.install_id)
         AND p.install_id IN (${GENUINE_INSTALLS_SQL})
     ) GROUP BY ${column}`
  ).bind(cutoff).all();
  return jsonResponse({
    window_days: windowDays,
    column,
    distribution: rows.results || [],
    computed_at: nowS,
  });
}

// ─── Router ─────────────────────────────────────────────────────────

const ROUTES = {
  "POST /v1/ping": handlePing,
  "GET /v1/health": async () => jsonResponse({ ok: true, ts: Math.floor(Date.now() / 1000) }),
  "GET /v1/stats/installs": (req, env, now) => statsInstalls(env, now),
  "GET /v1/stats/subgen-mix": (req, env, now) => statsSubgenMix(env, now),
  "GET /v1/stats/integrations": (req, env, now) => statsIntegrations(env, now),
  "GET /v1/stats/library-size": (req, env, now) => statsByColumn(env, now, "library_bucket"),
  "GET /v1/stats/walks-per-day": (req, env, now) => statsByColumn(env, now, "walks_per_day"),
  "GET /v1/stats/scheduler-modes": (req, env, now) => statsByColumn(env, now, "scheduler_mode"),
  // Version adoption — the release-rollout instrument. 30d = the fleet
  // picture; 7d = fresh enough to watch a release (or a launch-post influx)
  // land in near-real-time. Edge-cached like every stats read.
  "GET /v1/stats/versions": (req, env, now) => statsByColumn(env, now, "subarr_version"),
  "GET /v1/stats/versions-7d": (req, env, now) => statsByColumn(env, now, "subarr_version", 7),
};

// Public read-only aggregates change at most once per ping cycle (daily),
// so edge-cache them: a front-page link (r/sonarr etc.) would otherwise hit
// D1 uncached on every page load. With this, each CF colo collapses its
// herd to ~one D1 read per TTL. /ping + /health stay uncached (no-store).
const STATS_CACHE_TTL_S = 300;

export function isCacheableStats(method, pathname) {
  return method === "GET" && pathname.startsWith("/v1/stats/");
}

function withCors(res, cors) {
  // Clone so we never mutate a cached Response's immutable headers, and so a
  // cross-origin hit gets ITS Access-Control-Allow-Origin, not the first
  // caller's (the cached copy is stored without CORS headers).
  const out = new Response(res.body, res);
  for (const [k, v] of Object.entries(cors)) out.headers.set(k, v);
  return out;
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const origin = request.headers.get("Origin");
    const cors = corsHeaders(env, origin);
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: cors });
    }

    const cacheable = isCacheableStats(request.method, url.pathname);
    const cache = caches.default;
    if (cacheable) {
      const hit = await cache.match(request);
      if (hit) return withCors(hit, cors);
    }

    const key = `${request.method} ${url.pathname}`;
    const handler = ROUTES[key];
    if (!handler) {
      return new Response("not found", { status: 404, headers: cors });
    }
    const nowS = Math.floor(Date.now() / 1000);
    try {
      const res = await handler(request, env, nowS);
      if (cacheable && res.status === 200) {
        // Make it edge-cacheable, then store a CORS-free copy (CORS is added
        // fresh per request above + below). waitUntil so caching never delays
        // the response.
        res.headers.set("Cache-Control", `public, s-maxage=${STATS_CACHE_TTL_S}, max-age=${STATS_CACHE_TTL_S}`);
        ctx.waitUntil(cache.put(request, res.clone()));
      }
      return withCors(res, cors);
    } catch (e) {
      console.error("worker error:", e?.stack || e);
      return jsonResponse({ ok: false, reason: "internal error" }, 500, cors);
    }
  },
};
