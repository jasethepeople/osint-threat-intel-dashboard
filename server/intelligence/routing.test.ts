import { describe, expect, it } from "vitest";
import { matchesAlertRoute } from "./routing";

const threat = {
  sourceExternalId: "sample",
  title: "Container platform advisory",
  description: "Source-derived record",
  affectedStack: ["Kubernetes", "npm/react"],
  sourceUrl: "https://example.test/advisory",
  rawText: "source",
  severity: "High" as const,
  extractedGeoTags: [],
  geoObservations: [],
  zeroDayFlag: false,
  knownExploitedFlag: true,
  rawContentHash: "x".repeat(64),
};

describe("alert routing", () => {
  it("requires a watchlist stack match when a route is scoped", () => {
    expect(matchesAlertRoute(threat, { watchlistId: 1, minSeverity: "Critical", includeZeroDays: false, includeKnownExploited: true }, [{ id: 1, stackTerms: ["kubernetes"] }])).toBe(true);
    expect(matchesAlertRoute(threat, { watchlistId: 1, minSeverity: "Critical", includeZeroDays: false, includeKnownExploited: true }, [{ id: 1, stackTerms: ["postgres"] }])).toBe(false);
  });

  it("matches a global severity rule without inventing a stack hit", () => {
    expect(matchesAlertRoute(threat, { watchlistId: null, minSeverity: "High", includeZeroDays: false, includeKnownExploited: false }, [])).toBe(true);
  });
});
