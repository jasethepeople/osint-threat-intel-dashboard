import { describe, expect, it } from "vitest";
import { buildReportPayload } from "./report";

describe("report payload assembly", () => {
  it("bounds report entries and normalizes an auditable excerpt", () => {
    const result = buildReportPayload({
      generatedAt: new Date("2026-08-21T12:00:00Z"),
      counts: { Critical: 1, High: 2, Medium: 3, Low: 4 },
      dailyDigest: "Source-grounded digest.",
      threats: Array.from({ length: 10 }, (_, index) => ({ identifier: `CVE-2026-${index}`, severity: "High" as const, title: `Threat ${index}`, sourceUrl: "https://example.test" })),
      auditEvents: Array.from({ length: 8 }, (_, index) => ({ createdAt: "2026-08-21T12:00:00Z", eventType: "threat.extracted", eventHash: `abcdef0123456789${index}` })),
    });
    expect(result.topThreats).toHaveLength(8);
    expect(result.auditExcerpt).toHaveLength(6);
    expect(result.auditExcerpt[0]?.eventHash).toBe("abcdef0123456789");
    expect(result.triage.Critical).toBe(1);
  });
});
