import { describe, expect, it } from "vitest";
import { mlModelUsed } from "./scan";

describe("mlModelUsed", () => {
  it("follows explanation.ml.available when the scan records it", () => {
    expect(mlModelUsed({ explanation: { ml: { available: false, ml_score: 0 } }, model_version: "model-7" })).toBe(false);
    expect(mlModelUsed({ explanation: { ml: { available: true } }, model_version: null })).toBe(true);
  });

  it("falls back to the recorded model version", () => {
    expect(mlModelUsed({ explanation: null, model_version: null })).toBe(false);
    expect(mlModelUsed({ explanation: { ml: { available: "yes" } }, model_version: "model-7" })).toBe(true);
  });

  it("is unknown for scans that record neither", () => {
    expect(mlModelUsed({})).toBeNull();
    expect(mlModelUsed({ explanation: { ml: "unavailable" } })).toBeNull();
  });
});
