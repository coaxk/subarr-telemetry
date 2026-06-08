// Unit tests for the validation + rate-limit layer. The full Worker
// fetch test (HTTP end-to-end) lives in worker.integration.test.js and
// requires the @cloudflare/vitest-pool-workers runtime.
import { describe, it, expect } from "vitest";
import { validatePayload } from "../src/worker.js";

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
