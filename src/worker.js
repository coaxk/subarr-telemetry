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
         walks_per_day, error_counts_json, crashes_json, raw_payload_json
       ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
    ).bind(
      payload.install_id, nowS, payload.sent_at ?? null,
      payload.subarr_version ?? null, payload.python_version ?? null,
      payload.os_arch ?? null, payload.docker_tier ?? null,
      payload.subgen_kind ?? null, payload.subgen_version ?? null,
      integrationsJson, payload.library_bucket ?? null,
      payload.scheduler_mode ?? null,
      payload.walks_per_day_30d ?? null,
      errorCountsJson, crashesJson, rawPayloadJson,
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

// Total active installs in the last N days, computed from distinct
// install_ids in `pings` with received_at within the window.
async function statsInstalls(env, nowS) {
  const day = 86400;
  const [d7, d30, total] = await Promise.all([
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
const STATS_COLUMNS = new Set(["library_bucket", "walks_per_day", "scheduler_mode"]);

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
};

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const origin = request.headers.get("Origin");
    const cors = corsHeaders(env, origin);
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: cors });
    }
    const key = `${request.method} ${url.pathname}`;
    const handler = ROUTES[key];
    if (!handler) {
      return new Response("not found", { status: 404, headers: cors });
    }
    const nowS = Math.floor(Date.now() / 1000);
    try {
      const res = await handler(request, env, nowS);
      // Merge CORS into whatever the handler returned.
      for (const [k, v] of Object.entries(cors)) res.headers.set(k, v);
      return res;
    } catch (e) {
      console.error("worker error:", e?.stack || e);
      return jsonResponse({ ok: false, reason: "internal error" }, 500, cors);
    }
  },
};
