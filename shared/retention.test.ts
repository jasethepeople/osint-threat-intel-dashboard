import { describe, expect, it } from "vitest";
import { isEligibleForRetention, retentionCutoff } from "./retention";

describe("retention window", () => {
  it("uses an exact inclusive policy cutoff without deleting records at the boundary", () => {
    const now = new Date("2026-08-21T12:00:00.000Z");
    expect(retentionCutoff(30, now).toISOString()).toBe("2026-07-22T12:00:00.000Z");
    expect(isEligibleForRetention(new Date("2026-07-22T11:59:59.999Z"), 30, now)).toBe(true);
    expect(isEligibleForRetention(new Date("2026-07-22T12:00:00.000Z"), 30, now)).toBe(false);
  });
});
