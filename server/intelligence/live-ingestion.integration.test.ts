import { describe, expect, it } from "vitest";
import { listAuditEvents, listIntelligenceSources, listThreats } from "../db";
import { resealAuditChain, verifyAuditChain } from "./audit";
import { ingestSource } from "./service";

const liveIt = process.env.RUN_LIVE_INGESTION === "1" ? it : it.skip;

describe("live SecurityWeek ingestion", () => {
  liveIt("persists public source records and appends a verifiable audit chain", async () => {
    await resealAuditChain();
    const source = (await listIntelligenceSources()).find(candidate => candidate.sourceKey === "securityweek-rss");
    expect(source).toBeDefined();
    if (!source) return;

    const outcome = await ingestSource(source.id, { kind: "system", id: "integration-qa" });
    expect(outcome.status).toBe("completed");
    expect(outcome.itemsFetched).toBeGreaterThan(0);

    const threats = await listThreats(40);
    expect(threats.some(threat => threat.sourceId === source.id)).toBe(true);
    const audit = await listAuditEvents(200);
    expect(audit.some(event => event.eventType === "ingestion.completed" && event.entityId === String(source.id))).toBe(true);
    expect((await verifyAuditChain()).valid).toBe(true);
  }, 90_000);
});
