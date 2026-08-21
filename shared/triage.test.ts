import { describe, expect, it } from "vitest";
import { matchesTriageScope } from "./triage";

describe("business-unit triage scope", () => {
  it("requires both selected severity and an affected-stack match", () => {
    const scope = { stackTerms: ["kubernetes", "react"], severities: ["Critical", "High"] };
    expect(matchesTriageScope({ severity: "High", affectedStack: ["Kubernetes"] }, scope)).toBe(true);
    expect(matchesTriageScope({ severity: "Low", affectedStack: ["Kubernetes"] }, scope)).toBe(false);
    expect(matchesTriageScope({ severity: "High", affectedStack: ["PostgreSQL"] }, scope)).toBe(false);
  });
});
