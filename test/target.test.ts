import test from "node:test";
import assert from "node:assert/strict";
import path from "node:path";

import { resolveTarget } from "../src/target";

test("resolveTarget keeps absolute targets absolute", () => {
  const prev = process.env.GITHUB_WORKSPACE;
  process.env.GITHUB_WORKSPACE = "/workspace/repo";
  try {
    assert.equal(resolveTarget("/tmp/project"), path.resolve("/tmp/project"));
  } finally {
    if (prev === undefined) {
      delete process.env.GITHUB_WORKSPACE;
    } else {
      process.env.GITHUB_WORKSPACE = prev;
    }
  }
});

test("resolveTarget resolves relative targets against GITHUB_WORKSPACE", () => {
  const prev = process.env.GITHUB_WORKSPACE;
  process.env.GITHUB_WORKSPACE = "/workspace/repo";
  try {
    assert.equal(resolveTarget("services/api"), path.resolve("/workspace/repo/services/api"));
  } finally {
    if (prev === undefined) {
      delete process.env.GITHUB_WORKSPACE;
    } else {
      process.env.GITHUB_WORKSPACE = prev;
    }
  }
});

test("resolveTarget falls back to process cwd without GITHUB_WORKSPACE", () => {
  const prev = process.env.GITHUB_WORKSPACE;
  delete process.env.GITHUB_WORKSPACE;
  try {
    assert.equal(resolveTarget("."), path.resolve("."));
  } finally {
    if (prev !== undefined) process.env.GITHUB_WORKSPACE = prev;
  }
});
