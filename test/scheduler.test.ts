import test from "node:test";
import assert from "node:assert/strict";

import {
  mapConcurrent,
  mapConcurrentWithBarriers,
  parseMaxConcurrency,
} from "../src/scheduler";

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

test("parseMaxConcurrency accepts defaults and values in range", () => {
  assert.equal(parseMaxConcurrency("", 2, 7), 2);
  assert.equal(parseMaxConcurrency(" 1 ", 2, 7), 1);
  assert.equal(parseMaxConcurrency("7", 2, 7), 7);
});

test("parseMaxConcurrency rejects malformed and out-of-range values", () => {
  for (const value of ["0", "8", "2.5", "2x", "-1"]) {
    assert.throws(() => parseMaxConcurrency(value, 2, 7), {
      message: "max-concurrency must be an integer between 1 and 7",
    });
  }
});

test("mapConcurrent limits active tasks and preserves input order", async () => {
  let active = 0;
  let peak = 0;

  const results = await mapConcurrent([30, 5, 20, 1], 2, async (milliseconds) => {
    active += 1;
    peak = Math.max(peak, active);
    await delay(milliseconds);
    active -= 1;
    return milliseconds;
  });

  assert.equal(peak, 2);
  assert.deepEqual(results, [30, 5, 20, 1]);
});

test("mapConcurrent validates the concurrency limit", async () => {
  await assert.rejects(() => mapConcurrent([1], 0, async (value) => value), {
    message: "maxConcurrency must be a positive integer",
  });
});

test("mapConcurrentWithBarriers runs barriers without overlapping other tasks", async () => {
  const items = ["semgrep", "eslint", "spotbugs", "trivy", "gitleaks"];
  let activeReaders = 0;
  let barrierFinished = false;

  const results = await mapConcurrentWithBarriers(
    items,
    2,
    (engine) => engine === "spotbugs",
    async (engine) => {
      if (engine === "spotbugs") {
        assert.equal(activeReaders, 0);
        await delay(5);
        barrierFinished = true;
        return engine;
      }

      if (engine === "trivy" || engine === "gitleaks") {
        assert.equal(barrierFinished, true);
      }
      activeReaders += 1;
      await delay(10);
      activeReaders -= 1;
      return engine;
    },
  );

  assert.deepEqual(results, items);
});
