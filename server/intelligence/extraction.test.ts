import { describe, expect, it } from "vitest";
import { enrichThreat, extractCveId, severityFromScore } from "./extraction";

describe("threat extraction", () => {
  it("extracts an identifier and deterministic severity tiers", () => {
    expect(extractCveId("Patch CVE-2026-12345 immediately")).toBe("CVE-2026-12345");
    expect(severityFromScore(9.0)).toBe("Critical");
    expect(severityFromScore(7.2)).toBe("High");
    expect(severityFromScore(4.0)).toBe("Medium");
    expect(severityFromScore(3.9)).toBe("Low");
  });

  it("retains source data while deriving stack, geo, and zero-day indicators", () => {
    const enriched = enrichThreat({
      sourceExternalId: "case-1",
      title: "CVE-2026-12345 affects GitLab deployments",
      description: "Researchers in Germany report this flaw is actively exploited in the wild.",
      sourceUrl: "https://example.test/advisory",
      cvssScore: 9.4,
      affectedStack: ["npm/example"],
      rawText: "GitLab operators should apply the patch.",
    });

    expect(enriched.cveId).toBe("CVE-2026-12345");
    expect(enriched.severity).toBe("Critical");
    expect(enriched.affectedStack).toContain("GitLab");
    expect(enriched.extractedGeoTags).toContain("Germany");
    expect(enriched.zeroDayFlag).toBe(true);
    expect(enriched.knownExploitedFlag).toBe(true);
    expect(enriched.rawContentHash).toHaveLength(64);
  });
});
