// Retention for pings.raw_payload_json (issue #2, part 3).
//
// pings is append-only and every row carries the full payload as JSON, which is
// about half the database. Nothing reads it except the occasional corpus refresh
// for test/corpus/real-pings.json. The rule: blank raw payloads older than
// RAW_PAYLOAD_RETENTION_DAYS, but keep each install's LATEST ping intact, so a
// sample of every version ever seen in the wild survives for that corpus. Rows
// and their derived columns are never touched; only the raw copy goes.
//
// These tests run the real SQL on a real SQLite engine (node:sqlite), through a
// thin adapter shaped like D1's prepare().bind().run(). A string-matching test
// could not tell whether the UPDATE blanks the right rows, or whether its plan
// rescans the table once per row (D1 bills rows read, and install_id has no
// index).
import { describe, it, expect, beforeEach } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { DatabaseSync } from "node:sqlite";
import worker, {
  PRUNE_RAW_PAYLOADS_SQL,
  RAW_PAYLOAD_RETENTION_DAYS,
  pruneRawPayloads,
} from "../src/worker.js";

const DAY = 86400;
const NOW = 1_800_000_000;

function d1(db) {
  return {
    prepare(sql) {
      const stmt = db.prepare(sql);
      return {
        bind: (...args) => ({
          run: async () => {
            const r = stmt.run(...args);
            return { success: true, meta: { changes: Number(r.changes) } };
          },
        }),
      };
    },
  };
}

function freshDb() {
  const db = new DatabaseSync(":memory:");
  const here = (p) => fileURLToPath(new URL(p, import.meta.url));
  for (const m of [
    "0001_baseline.sql",
    "0002_crashes.sql",
    "0003_retention_signals.sql",
    "0004_onboarding_funnel.sql",
    "0005_subgen_probe_cause.sql",
    "0006_onboarding_ui_seen.sql",
  ]) {
    db.exec(readFileSync(here(`../migrations/${m}`), "utf8"));
  }
  return db;
}

function ping(db, install, ageDays, version = "2.7.9") {
  db.prepare(
    "INSERT INTO pings (install_id, received_at, subarr_version, raw_payload_json) VALUES (?, ?, ?, ?)",
  ).run(install, NOW - Math.round(ageDays * DAY), version, JSON.stringify({ install_id: install, v: version }));
}

const rawOf = (db) =>
  db
    .prepare("SELECT install_id, received_at, subarr_version, raw_payload_json IS NOT NULL AS has_raw FROM pings ORDER BY rowid")
    .all()
    .map((r) => ({ ...r, has_raw: Number(r.has_raw) }));

describe("pruneRawPayloads", () => {
  let db;
  beforeEach(() => {
    db = freshDb();
  });

  it("blanks old raw payloads but keeps each install's latest ping, and never deletes a row", async () => {
    ping(db, "a", 200, "1.1.0"); // old, not latest -> blanked
    ping(db, "a", 120, "2.5.1"); // old, not latest -> blanked
    ping(db, "a", 100, "2.6.0"); // old but LATEST for a -> kept
    ping(db, "b", 300, "0.9.0"); // old, only ping -> latest -> kept
    ping(db, "c", 95, "2.7.0"); // old, not latest -> blanked
    ping(db, "c", 10, "2.7.9"); // recent -> kept

    const changed = await pruneRawPayloads(d1(db), NOW);

    expect(changed).toBe(3);
    expect(rawOf(db).map((r) => [r.install_id, r.subarr_version, r.has_raw])).toEqual([
      ["a", "1.1.0", 0],
      ["a", "2.5.1", 0],
      ["a", "2.6.0", 1],
      ["b", "0.9.0", 1],
      ["c", "2.7.0", 0],
      ["c", "2.7.9", 1],
    ]);
    // Derived columns survive: the stats read these, not the raw copy.
    expect(db.prepare("SELECT COUNT(*) AS n FROM pings WHERE subarr_version IS NOT NULL").get().n).toBe(6);
  });

  it("leaves anything younger than the retention window alone", async () => {
    ping(db, "a", RAW_PAYLOAD_RETENTION_DAYS - 1);
    ping(db, "a", 1);
    expect(await pruneRawPayloads(d1(db), NOW)).toBe(0);
    expect(rawOf(db).every((r) => r.has_raw === 1)).toBe(true);
  });

  it("works through a backlog in batches and stops at maxBatches", async () => {
    for (let i = 0; i < 7; i++) ping(db, "a", 200 + i);
    ping(db, "a", 1); // latest

    expect(await pruneRawPayloads(d1(db), NOW, { batch: 2, maxBatches: 2 })).toBe(4);
    expect(await pruneRawPayloads(d1(db), NOW, { batch: 2, maxBatches: 10 })).toBe(3);
    expect(await pruneRawPayloads(d1(db), NOW, { batch: 2, maxBatches: 10 })).toBe(0);
  });

  it("computes 'latest per install' once, not once per row (D1 bills rows read)", () => {
    const plan = db
      .prepare(`EXPLAIN QUERY PLAN ${PRUNE_RAW_PAYLOADS_SQL}`)
      .all(NOW - RAW_PAYLOAD_RETENTION_DAYS * DAY, 5000)
      .map((r) => r.detail)
      .join("\n");
    expect(plan).not.toMatch(/CORRELATED/i);
  });
});

describe("the worker actually runs it", () => {
  it("exports a scheduled handler that prunes", async () => {
    expect(typeof worker.scheduled).toBe("function");
    const db = freshDb();
    ping(db, "a", 200);
    ping(db, "a", 1);
    const waits = [];
    await worker.scheduled({ scheduledTime: NOW * 1000 }, { DB: d1(db) }, { waitUntil: (p) => waits.push(p) });
    await Promise.all(waits);
    expect(rawOf(db).map((r) => r.has_raw)).toEqual([0, 1]);
  });

  it("wrangler.toml declares a cron trigger, or the handler never fires", () => {
    const toml = readFileSync(fileURLToPath(new URL("../wrangler.toml", import.meta.url)), "utf8");
    expect(toml).toMatch(/^\[triggers\]\s*\n\s*crons\s*=\s*\[\s*"[^"]+"\s*\]/m);
  });
});
