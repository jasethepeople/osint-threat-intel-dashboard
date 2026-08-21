import { describe, expect, it } from "vitest";
import { filterRetentionTimeline, retentionPayloadValue } from "./retention-timeline";

const events = [
  { id: 1, eventType: "retention.configured", payload: { retentionDays: 90 }, createdAt: new Date("2026-08-20T00:00:00Z"), actorKind: "user", eventHash: "a", previousHash: null },
  { id: 2, eventType: "retention.completed", payload: { batchId: "batch-a", archiveCount: 3 }, createdAt: new Date("2026-08-21T00:00:00Z"), actorKind: "system", eventHash: "b", previousHash: "a" },
];

describe("retention timeline", () => {
  it("separates completed purge batches from policy configuration evidence", () => {
    expect(filterRetentionTimeline(events, "purges").map(event => event.id)).toEqual([2]);
    expect(filterRetentionTimeline(events, "configuration").map(event => event.id)).toEqual([1]);
  });

  it("reads scalar batch metadata without coercing nested payloads", () => {
    expect(retentionPayloadValue(events[1].payload, "batchId")).toBe("batch-a");
    expect(retentionPayloadValue({ nested: { value: true } }, "nested")).toBe("");
  });
});
