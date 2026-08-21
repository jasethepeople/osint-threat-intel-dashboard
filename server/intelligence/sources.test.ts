import { afterEach, describe, expect, it, vi } from "vitest";
import { fetchSourceThreats } from "./sources";

const source = {
  id: 1,
  sourceKey: "github-global-advisories",
  name: "GitHub",
  kind: "github" as const,
  endpoint: "https://api.github.com/advisories",
  enabled: true,
  pollIntervalMinutes: 30,
  scheduleCronTaskUid: null,
  lastCursor: null,
  lastSuccessAt: null,
  lastError: null,
  createdAt: new Date(),
  updatedAt: new Date(),
};

afterEach(() => vi.unstubAllGlobals());

describe("source normalization", () => {
  it("normalizes a public GitHub advisory without inventing source fields", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify([{
      ghsa_id: "GHSA-test-0001", cve_id: "CVE-2026-0001", summary: "Package issue", description: "A test advisory", html_url: "https://github.com/advisories/GHSA-test-0001", severity: "high", published_at: "2026-08-20T12:00:00Z", updated_at: "2026-08-21T12:00:00Z", cvss: { score: 8.1 }, vulnerabilities: [{ package: { ecosystem: "npm", name: "example-package" } }], references: [],
    }])), { ok: true }));

    const threats = await fetchSourceThreats(source);

    expect(threats).toHaveLength(1);
    expect(threats[0]).toMatchObject({ cveId: "CVE-2026-0001", ghsaId: "GHSA-test-0001", severity: "High", cvssScore: 8.1, affectedStack: ["npm/example-package"] });
  });

  it("surfaces non-success source responses for the ingestion run to record", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("rate limited", { status: 429 })));
    await expect(fetchSourceThreats(source)).rejects.toThrow("Source request failed (429)");
  });
});
