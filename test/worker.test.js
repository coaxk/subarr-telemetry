// Unit tests for the validation + rate-limit layer. The full Worker
// fetch test (HTTP end-to-end) lives in worker.integration.test.js and
// requires the @cloudflare/vitest-pool-workers runtime.
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { validatePayload, isCacheableStats } from "../src/worker.js";

describe("isCacheableStats — edge-cache only the public read aggregates", () => {
  it("caches GET /v1/stats/*", () => {
    expect(isCacheableStats("GET", "/v1/stats/installs")).toBe(true);
    expect(isCacheableStats("GET", "/v1/stats/subgen-mix")).toBe(true);
  });
  it("never caches the ping ingest or health", () => {
    expect(isCacheableStats("POST", "/v1/ping")).toBe(false);
    expect(isCacheableStats("GET", "/v1/health")).toBe(false);
  });
  it("only caches GET (a stats POST, if any, is not cached)", () => {
    expect(isCacheableStats("POST", "/v1/stats/installs")).toBe(false);
  });
});

describe("validatePayload — real-fleet corpus replay", () => {
  // 60 verbatim raw_payload_json rows sampled from production D1 across
  // every subarr version in the wild (0.1.0 → 1.5.x), install_ids rewritten
  // to synthetic hex. EVERY payload a real client ever successfully sent
  // must validate forever — this single test would have caught BOTH the
  // docker_tier and library_bucket fleet outages before deploy. If a
  // hardening change fails this test, the hardening is wrong, not the
  // corpus. Refresh occasionally: see issue #1 for the sampling query.
  const corpus = JSON.parse(
    readFileSync(fileURLToPath(new URL("./corpus/real-pings.json", import.meta.url)), "utf8"),
  );

  it("loads a meaningfully sized corpus", () => {
    expect(corpus.length).toBeGreaterThanOrEqual(50);
  });

  for (const [i, payload] of corpus.entries()) {
    it(`accepts corpus payload ${i} (subarr ${payload.subarr_version})`, () => {
      const v = validatePayload(payload);
      expect(v.ok, `rejected: ${v.reason}`).toBe(true);
    });
  }
});

describe("validatePayload — real client payloads (regression pins)", () => {
  // The 2026-06-08 value-validation hardening shipped with no test using a
  // REAL subarr payload — and silently 400-rejected every ping fleet-wide
  // for 3 days (subarr sends docker_tier as a NUMBER; the validator
  // demanded a string). This is subarr 1.4.0's verbatim payload: it must
  // accept FOREVER. If a future hardening breaks this test, the hardening
  // is wrong, not the test.
  const SUBARR_140_PAYLOAD = {
    install_id: "fd19004ba4e14885910c09d06ff8cc71",
    sent_at: 1781129058.97,
    subarr_version: "1.4.0",
    python_version: "3.12.13",
    os_arch: "Linux/x86_64",
    subgen_kind: "subarr-subgen",
    subgen_version: "2026.05.3",
    integrations: { bazarr: true, sonarr: true, radarr: true, tautulli: true, plex: true, ollama: true },
    library_bucket: "1k-10k",
    scheduler_enabled: false,
    scheduler_mode: null,
    walks_per_day_30d: 8.63,
    error_counts_30d: {},
    docker_tier: 1,
  };

  it("accepts subarr 1.4.0's verbatim payload (numeric docker_tier)", () => {
    const v = validatePayload(SUBARR_140_PAYLOAD);
    expect(v.ok).toBe(true);
    expect(v.value.docker_tier).toBe("1"); // coerced for storage
  });

  it("still accepts string docker_tier", () => {
    const v = validatePayload({ ...SUBARR_140_PAYLOAD, docker_tier: "tier3" });
    expect(v.ok).toBe(true);
    expect(v.value.docker_tier).toBe("tier3");
  });

  it("rejects non-finite numeric docker_tier", () => {
    const v = validatePayload({ ...SUBARR_140_PAYLOAD, docker_tier: Infinity });
    expect(v.ok).toBe(false);
  });

  // Every bucket literal subarr has EVER shipped must accept forever. The
  // 06-08 hardening's XSS_CHARS check 400-rejected "<100" — the bucket
  // ~99.5% of the fleet reports (installs that never ran a probe walk) —
  // silently cutting fleet telemetry to near zero even after the
  // docker_tier fix. Field validation on non-critical fields must drop the
  // FIELD, never the ping.
  for (const bucket of ["<100", "100-1k", "1k-10k", ">10k", "unknown"]) {
    it(`accepts library_bucket ${JSON.stringify(bucket)}`, () => {
      const v = validatePayload({ ...SUBARR_140_PAYLOAD, library_bucket: bucket });
      expect(v.ok).toBe(true);
      expect(v.value.library_bucket).toBe(bucket);
    });
  }

  it("drops an unknown library_bucket instead of rejecting the ping", () => {
    const v = validatePayload({ ...SUBARR_140_PAYLOAD, library_bucket: "<script>alert(1)</script>" });
    expect(v.ok).toBe(true);
    expect(v.value.library_bucket).toBeNull();
  });

  it("accepts install_age_days + data_persistent", () => {
    const v = validatePayload({ ...SUBARR_140_PAYLOAD, install_age_days: 42.0, data_persistent: true });
    expect(v.ok).toBe(true);
    expect(v.value.install_age_days).toBe(42.0);
    expect(v.value.data_persistent).toBe(true);
  });

  it("drops a bad install_age_days / data_persistent, never rejects the ping", () => {
    const v = validatePayload({
      ...SUBARR_140_PAYLOAD,
      install_age_days: "ancient",
      data_persistent: "yes",
    });
    expect(v.ok).toBe(true);
    expect(v.value.install_age_days).toBeNull();
    expect(v.value.data_persistent).toBeNull();
  });

  it("forwards-compatible: a future field is dropped, ping still accepted", () => {
    const v = validatePayload({ ...SUBARR_140_PAYLOAD, some_future_metric: 7 });
    expect(v.ok).toBe(true);
    expect(v.value.some_future_metric).toBeUndefined();
  });
});

describe("validatePayload — crash_counts_24h (#157 Phase 2)", () => {
  const BASE = { install_id: "abcdef1234567890", subarr_version: "1.5.0" };

  it("accepts a sanitized crash-aggregate object", () => {
    const v = validatePayload({
      ...BASE,
      crash_counts_24h: { "NameError:coverage_engine:1639": 4, "TimeoutError:subgen_client:142": 1 },
    });
    expect(v.ok).toBe(true);
    expect(v.value.crash_counts_24h["NameError:coverage_engine:1639"]).toBe(4);
  });

  it("rejects markup in crash keys (stored-XSS guard)", () => {
    const v = validatePayload({ ...BASE, crash_counts_24h: { "<script>:x:1": 1 } });
    expect(v.ok).toBe(false);
  });

  it("rejects non-number crash values", () => {
    const v = validatePayload({ ...BASE, crash_counts_24h: { "ValueError:paths:30": "lots" } });
    expect(v.ok).toBe(false);
  });

  it("rejects more than 64 crash keys", () => {
    const big = {};
    for (let i = 0; i < 65; i++) big[`E${i}:mod:${i}`] = 1;
    const v = validatePayload({ ...BASE, crash_counts_24h: big });
    expect(v.ok).toBe(false);
  });
});

describe("validatePayload — allow-list enforcement", () => {
  it("accepts a minimal valid payload", () => {
    const v = validatePayload({
      install_id: "abcdef1234567890",
      subarr_version: "1.0.0",
      subgen_kind: "subarr-subgen",
    });
    expect(v.ok).toBe(true);
    expect(v.value.install_id).toBe("abcdef1234567890");
    expect(v.value.subarr_version).toBe("1.0.0");
  });

  it("drops unknown allowed-looking fields silently", () => {
    const v = validatePayload({
      install_id: "abcdef1234567890",
      subarr_version: "1.0.0",
      unknown_future_field: "anything",
    });
    expect(v.ok).toBe(true);
    expect(v.value.unknown_future_field).toBeUndefined();
  });

  // Privacy enforcement — these MUST be rejected, not just dropped.
  // Mirrors subarr's test_payload_never_includes_forbidden_fields.

  it("rejects payloads containing file paths", () => {
    const v = validatePayload({ install_id: "abcdef1234567890", path: "/media/library/x.mkv" });
    expect(v.ok).toBe(false);
    expect(v.reason).toMatch(/forbidden/);
  });

  it("rejects payloads containing api keys", () => {
    const v = validatePayload({ install_id: "abcdef1234567890", api_key: "secret" });
    expect(v.ok).toBe(false);
  });

  it("rejects payloads containing tokens", () => {
    const v = validatePayload({ install_id: "abcdef1234567890", token: "xoxb-..." });
    expect(v.ok).toBe(false);
  });

  it("rejects payloads containing hostnames", () => {
    const v = validatePayload({ install_id: "abcdef1234567890", hostname: "homeserver" });
    expect(v.ok).toBe(false);
  });

  it("rejects payloads containing IP addresses", () => {
    const v = validatePayload({ install_id: "abcdef1234567890", ip: "192.168.1.1" });
    expect(v.ok).toBe(false);
  });

  it("rejects payloads containing language identifiers", () => {
    const v = validatePayload({ install_id: "abcdef1234567890", language: "fr" });
    expect(v.ok).toBe(false);
  });

  it("rejects payloads containing user identifiers", () => {
    const v = validatePayload({ install_id: "abcdef1234567890", username: "judd" });
    expect(v.ok).toBe(false);
    const v2 = validatePayload({ install_id: "abcdef1234567890", email: "x@y.z" });
    expect(v2.ok).toBe(false);
  });

  // Defense in depth: install_id field itself can't smuggle PII.

  it("rejects install_id that looks like an email", () => {
    const v = validatePayload({ install_id: "user@host" });
    expect(v.ok).toBe(false);
  });

  it("rejects install_id shorter than 8 chars", () => {
    const v = validatePayload({ install_id: "abc" });
    expect(v.ok).toBe(false);
  });

  it("accepts install_id that's a 32-char hex UUID (long form OK)", () => {
    // 32 chars with a dot would be rejected by the short rule, so verify
    // a normal UUID passes. UUIDs from subarr are 32 hex chars no dots.
    const v = validatePayload({
      install_id: "fd19004ba4e14885910c09d06ff8cc71",
    });
    expect(v.ok).toBe(true);
  });

  it("rejects non-object payloads", () => {
    expect(validatePayload(null).ok).toBe(false);
    expect(validatePayload([]).ok).toBe(false);
    expect(validatePayload("string").ok).toBe(false);
  });

  // Field families we want to support cleanly.

  it("accepts nested integrations object", () => {
    const v = validatePayload({
      install_id: "abcdef1234567890",
      integrations: { bazarr: true, sonarr: true, tautulli: false },
    });
    expect(v.ok).toBe(true);
    expect(v.value.integrations.bazarr).toBe(true);
  });

  it("accepts library_bucket coarse string", () => {
    const v = validatePayload({
      install_id: "abcdef1234567890",
      library_bucket: "1k_10k",
    });
    expect(v.ok).toBe(true);
    expect(v.value.library_bucket).toBe("1k_10k");
  });
});

describe("validatePayload — value-level validation (anti-XSS / anti-secret)", () => {
  const base = "abcdef1234567890";

  it("rejects markup in a rendered string field (stored XSS guard)", () => {
    const v = validatePayload({
      install_id: base,
      subgen_kind: '<img src=x onerror=alert(1)>',
    });
    expect(v.ok).toBe(false);
    expect(v.reason).toMatch(/invalid characters/);
  });

  it("rejects markup in an integration key (rendered on stats page)", () => {
    const v = validatePayload({
      install_id: base,
      integrations: { "<svg/onload=alert(1)>": true },
    });
    expect(v.ok).toBe(false);
  });

  it("rejects an oversize string value", () => {
    const v = validatePayload({ install_id: base, subarr_version: "x".repeat(65) });
    expect(v.ok).toBe(false);
    expect(v.reason).toMatch(/too long/);
  });

  it("rejects a secret smuggled into an allowed field", () => {
    const v = validatePayload({ install_id: base, subarr_version: "Bearer sk-abcdefghijkl" });
    expect(v.ok).toBe(false);
    expect(v.reason).toMatch(/secret/);
  });

  it("rejects a 32-hex (api-key-shaped) value in an allowed field", () => {
    const v = validatePayload({ install_id: base, subgen_version: "0123456789abcdef0123456789abcdef" });
    expect(v.ok).toBe(false);
  });

  it("rejects non-boolean/number integration values", () => {
    const v = validatePayload({ install_id: base, integrations: { bazarr: "yes" } });
    expect(v.ok).toBe(false);
  });

  it("rejects out-of-range walks_per_day_30d", () => {
    expect(validatePayload({ install_id: base, walks_per_day_30d: -1 }).ok).toBe(false);
    expect(validatePayload({ install_id: base, walks_per_day_30d: 999999 }).ok).toBe(false);
    expect(validatePayload({ install_id: base, walks_per_day_30d: "5" }).ok).toBe(false);
  });

  it("accepts a normal walks_per_day_30d number", () => {
    const v = validatePayload({ install_id: base, walks_per_day_30d: 12 });
    expect(v.ok).toBe(true);
    expect(v.value.walks_per_day_30d).toBe(12);
  });
});
