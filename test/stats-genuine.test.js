// Guards subarr #473's consequence for the PUBLIC stats surface.
//
// Every install-count endpoint used to be COUNT(DISTINCT install_id) over raw
// pings. An install whose /data is not a real mount mints a new id on every
// restart, so those counts ran ~80x high and, worse, distorted the SHAPE of
// the version chart: the versions that churned hardest were the ones our own
// old README broke, so they dominated a ranking that implied nobody upgrades.
//
// The failure mode this file exists to catch is not a wrong number today. It
// is a stats endpoint added LATER that queries `pings` and forgets the filter,
// reintroducing the inflation on one card while the others stay honest. That
// is invisible in review and invisible in output, because a plausible large
// number looks like good news.
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { GENUINE_INSTALLS_SQL } from "../src/worker.js";

const SOURCE = readFileSync(
  fileURLToPath(new URL("../src/worker.js", import.meta.url)),
  "utf8",
);

// Pull out each `async function stats*(...) { ... }` body by brace matching.
// Brace matching rather than a regex because the bodies contain both template
// literals and nested braces, and a lazy regex silently truncates at the first
// `}` inside a query string -- which would make this test pass by looking at
// almost none of the function.
function statsFunctions(src) {
  const out = {};
  const re = /async function (stats\w+)\s*\([^)]*\)\s*\{/g;
  let m;
  while ((m = re.exec(src)) !== null) {
    let depth = 1;
    let i = re.lastIndex;
    while (i < src.length && depth > 0) {
      const ch = src[i];
      if (ch === "{") depth += 1;
      else if (ch === "}") depth -= 1;
      i += 1;
    }
    out[m[1]] = src.slice(re.lastIndex, i);
  }
  return out;
}

const FNS = statsFunctions(SOURCE);

describe("the genuine-install definition itself", () => {
  it("carries BOTH signals, since neither alone is sufficient", () => {
    // data_persistent alone discards every genuine install on a client too old
    // to send the field. Recurrence alone discards genuine installs that
    // arrived today. Losing either silently biases the published number.
    expect(GENUINE_INSTALLS_SQL).toMatch(/data_persistent/);
    expect(GENUINE_INSTALLS_SQL).toMatch(/COUNT\(DISTINCT CAST\(received_at/);
    expect(GENUINE_INSTALLS_SQL).toMatch(/\bOR\b/);
  });

  it("treats a missing data_persistent as not-persistent, never as persistent", () => {
    // NULL is 'this client cannot tell us', which is the overwhelming majority
    // of rows (22,840 of 23,426 when measured). If NULL ever coalesced to 1,
    // the filter would pass the entire churned population and the endpoint
    // would silently return to publishing the inflated count.
    expect(GENUINE_INSTALLS_SQL).toMatch(/COALESCE\(data_persistent,\s*0\)/);
  });

  it("is a bare SELECT of install_id, so it composes into IN (...) and FROM (...)", () => {
    expect(GENUINE_INSTALLS_SQL).toMatch(/SELECT\s+install_id\s+FROM\s+pings/);
    expect(GENUINE_INSTALLS_SQL).not.toMatch(/;/);
  });
});

describe("every stats endpoint counts genuine installs", () => {
  it("found the stats functions to check (guards the extractor itself)", () => {
    // If the brace matcher or the naming convention ever breaks, this suite
    // would vacuously pass over an empty set while claiming full coverage.
    const names = Object.keys(FNS);
    expect(names).toEqual(expect.arrayContaining([
      "statsInstalls", "statsSubgenMix", "statsIntegrations", "statsByColumn",
    ]));
  });

  for (const [name, body] of Object.entries(FNS)) {
    it(`${name} filters to genuine installs`, () => {
      expect(
        body.includes("GENUINE_INSTALLS_SQL"),
        `${name} queries pings without the genuine-install filter, which ` +
        `reintroduces the subarr#473 inflation on whatever card it feeds`,
      ).toBe(true);
    });
  }
});

describe("statsInstalls keeps the raw numbers visible", () => {
  const body = FNS.statsInstalls;

  it("still publishes raw_* alongside the genuine headline", () => {
    // Dropping them would make the historical series unexplainable: anyone who
    // saw 17,417 needs to be able to see where it went.
    for (const f of ["raw_active_7d", "raw_active_30d", "raw_total_ever"]) {
      expect(body).toContain(f);
    }
  });

  it("says which of the two it is reporting as the headline", () => {
    expect(body).toMatch(/counting:\s*"genuine"/);
  });
});
