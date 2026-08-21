import { describe, expect, it } from "vitest";
import { sourceItemIdentity } from "./idempotency";

describe("source item idempotency identity", () => {
  it("is stable for a repeated source item and changes across source boundaries", () => {
    expect(sourceItemIdentity("nvd-cve", "CVE-2026-0001")).toBe(sourceItemIdentity("nvd-cve", "CVE-2026-0001"));
    expect(sourceItemIdentity("nvd-cve", "CVE-2026-0001")).not.toBe(sourceItemIdentity("github", "CVE-2026-0001"));
  });
});
