// The pings INSERT is hand-maintained: a column list, a literal run of `?`
// placeholders, and a separate .bind() argument list. Nothing makes the three
// agree, and a mismatch is not a compile error. Adding a column and forgetting
// one `?` shifts every subsequent value into the wrong column, which stores
// plausible-looking garbage rather than failing loudly.
//
// Added with subarr#479, which took the list from 20 columns to 22.
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const SOURCE = readFileSync(
  fileURLToPath(new URL("../src/worker.js", import.meta.url)),
  "utf8",
);

// Pull `INSERT INTO pings ( ... ) VALUES (...)` plus the .bind(...) that follows.
function parseInsert(src) {
  const start = src.indexOf("INSERT INTO pings");
  if (start === -1) return null;

  const colOpen = src.indexOf("(", start);
  const colClose = src.indexOf(")", colOpen);
  const columns = src
    .slice(colOpen + 1, colClose)
    .split(",")
    .map((c) => c.replace(/\/\/.*$/gm, "").trim())
    .filter(Boolean);

  const valuesAt = src.indexOf("VALUES", colClose);
  const vOpen = src.indexOf("(", valuesAt);
  const vClose = src.indexOf(")", vOpen);
  const placeholders = (src.slice(vOpen + 1, vClose).match(/\?/g) || []).length;

  // .bind( ... ) — count arguments at paren depth 1 so ternaries and nested
  // calls do not inflate the count.
  const bindAt = src.indexOf(".bind(", vClose);
  let i = src.indexOf("(", bindAt) + 1;
  let depth = 1;
  let args = 1;
  let sawContent = false;
  for (; i < src.length && depth > 0; i++) {
    const ch = src[i];
    if (ch === "(" || ch === "[" || ch === "{") depth++;
    else if (ch === ")" || ch === "]" || ch === "}") depth--;
    else if (ch === "," && depth === 1) args++;
    else if (depth === 1 && !/\s/.test(ch)) sawContent = true;
  }
  // A trailing comma before the closing paren counts one argument too many.
  const tail = src.slice(0, i - 1).replace(/\s+$/, "");
  if (tail.endsWith(",")) args--;

  return { columns, placeholders, args: sawContent ? args : 0 };
}

describe("the pings INSERT keeps its three lists in step", () => {
  const parsed = parseInsert(SOURCE);

  it("found the statement at all (guards the parser itself)", () => {
    // Without this the suite would vacuously pass if the parser broke or the
    // statement moved, while claiming to check it.
    expect(parsed).not.toBeNull();
    expect(parsed.columns.length).toBeGreaterThan(15);
  });

  it("has one placeholder per column", () => {
    expect(parsed.placeholders).toBe(parsed.columns.length);
  });

  it("has one bind argument per column", () => {
    expect(parsed.args).toBe(parsed.columns.length);
  });

  it("still writes the columns #479 added", () => {
    expect(parsed.columns).toContain("subgen_probe_failure");
    expect(parsed.columns).toContain("subgen_target_is_default");
  });

  it("writes the column #480 added", () => {
    expect(parsed.columns).toContain("onboarding_ui_seen");
  });

  it("keeps raw_payload_json last, so appends go before it", () => {
    expect(parsed.columns[parsed.columns.length - 1]).toBe("raw_payload_json");
  });
});

describe("the allow-list carries the #479 fields", () => {
  it("accepts both, or the worker silently drops them on insert", () => {
    // ALLOWED_FIELDS is the gate: a field absent here never reaches the row,
    // and nothing errors. The column would just stay NULL forever.
    expect(SOURCE).toContain('"subgen_probe_failure"');
    expect(SOURCE).toContain('"subgen_target_is_default"');
  });

  it("accepts onboarding_ui_seen (#480)", () => {
    expect(SOURCE).toContain('"onboarding_ui_seen"');
  });
});
