// subarr#582: an install configured entirely by environment variables never
// opens the wizard and never sets onboarding_complete, and was therefore
// counted as an onboarding loss. It is not one: it is working.
//
// Measured on genuine installs (latest ping, 30d): of the 41 non-finishers
// whose client reports `onboarding_ui_seen`, 15 had Bazarr connected, 15
// Sonarr, 10 a real library and 7 were actively walking. Blending those with
// the ~26 that configured nothing produced the "44% never finish" figure the
// activation work was about to be aimed at — the same class of fault as #473,
// where the metric described our own definition rather than the user.
//
// classifyOnboarding is pure so the buckets can be tested directly rather than
// inferred from an aggregate, which is what lets each rule below name the
// single input it turns on.
import { describe, it, expect } from "vitest";
import { classifyOnboarding, ONBOARDING_OUTCOMES } from "../src/worker.js";

const base = {
  onboarding_complete: 0,
  onboarding_ui_seen: 0,
  integrations_json: null,
  library_bucket: "<100",
  walks_per_day: 0,
};

const row = (over = {}) => ({ ...base, ...over });

describe("classifyOnboarding", () => {
  it("calls a finished install completed", () => {
    expect(classifyOnboarding(row({ onboarding_complete: 1 }))).toBe("completed");
  });

  it("calls it completed even when the client is too old to report ui_seen", () => {
    // ui_seen only starts recording when the page renders, so an install that
    // finished before the field shipped reports null forever. Completion is
    // still authoritative.
    expect(
      classifyOnboarding(row({ onboarding_complete: 1, onboarding_ui_seen: null })),
    ).toBe("completed");
  });

  it("calls an unfinished install with no ui_seen unknown, never a loss", () => {
    expect(classifyOnboarding(row({ onboarding_ui_seen: null }))).toBe("unknown");
  });

  it("calls an install that opened the wizard and stopped abandoned", () => {
    expect(classifyOnboarding(row({ onboarding_ui_seen: 1 }))).toBe("abandoned");
  });

  it("calls an install with nothing at all never_engaged", () => {
    expect(classifyOnboarding(row())).toBe("never_engaged");
  });

  // ── the point of the issue ──────────────────────────────────────────

  it("does not count an env-configured install as a loss (bazarr)", () => {
    const r = row({ integrations_json: JSON.stringify({ bazarr: true }) });
    expect(classifyOnboarding(r)).toBe("configured_without_wizard");
  });

  it("does not count an env-configured install as a loss (sonarr)", () => {
    const r = row({ integrations_json: JSON.stringify({ sonarr: true }) });
    expect(classifyOnboarding(r)).toBe("configured_without_wizard");
  });

  it("counts a real library as configured even with no integrations", () => {
    expect(classifyOnboarding(row({ library_bucket: "1k-10k" }))).toBe(
      "configured_without_wizard",
    );
  });

  it("treats every library bucket above <100 as real", () => {
    for (const b of ["100-1k", "1k-10k", ">10k"]) {
      expect(classifyOnboarding(row({ library_bucket: b }))).toBe(
        "configured_without_wizard",
      );
    }
  });

  it("does not treat a small library as configured", () => {
    expect(classifyOnboarding(row({ library_bucket: "<100" }))).toBe("never_engaged");
  });

  it("does not treat an integration that is present-but-false as configured", () => {
    const r = row({ integrations_json: JSON.stringify({ bazarr: false, sonarr: false }) });
    expect(classifyOnboarding(r)).toBe("never_engaged");
  });

  it("ignores integrations we do not count as evidence of a working install", () => {
    // ollama/tautulli are optional extras: having one says nothing about
    // whether the core setup was done.
    const r = row({ integrations_json: JSON.stringify({ ollama: true, tautulli: true }) });
    expect(classifyOnboarding(r)).toBe("never_engaged");
  });

  it("survives malformed integrations_json rather than throwing", () => {
    expect(classifyOnboarding(row({ integrations_json: "{not json" }))).toBe(
      "never_engaged",
    );
  });

  // ── precedence, stated explicitly ───────────────────────────────────

  it("prefers completed over everything else", () => {
    const r = row({
      onboarding_complete: 1,
      onboarding_ui_seen: 1,
      integrations_json: JSON.stringify({ bazarr: true }),
    });
    expect(classifyOnboarding(r)).toBe("completed");
  });

  it("prefers abandoned over configured: they opened it and stopped", () => {
    // Opening the wizard is the signal the abandonment question is about, so
    // it must not be masked by having integrations configured.
    const r = row({
      onboarding_ui_seen: 1,
      integrations_json: JSON.stringify({ bazarr: true }),
    });
    expect(classifyOnboarding(r)).toBe("abandoned");
  });

  it("returns only known outcomes, whatever it is handed", () => {
    const weird = [
      {},
      row({ onboarding_complete: null, onboarding_ui_seen: undefined }),
      row({ library_bucket: null }),
      row({ library_bucket: "nonsense" }),
      row({ walks_per_day: null }),
    ];
    for (const r of weird) {
      expect(ONBOARDING_OUTCOMES).toContain(classifyOnboarding(r));
    }
  });
});

describe("the published shape", () => {
  it("names every outcome it can emit", () => {
    expect([...ONBOARDING_OUTCOMES].sort()).toEqual([
      "abandoned",
      "completed",
      "configured_without_wizard",
      "never_engaged",
      "unknown",
    ]);
  });
});
