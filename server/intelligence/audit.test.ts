import { describe, expect, it } from "vitest";
import { hashAuditEvent, verifyAuditRecords, type AuditChainRecord } from "./audit";

function makeRecord(id: number, previousHash: string | null, eventType: string): AuditChainRecord {
  const createdAt = new Date(`2026-08-21T10:0${id}:00.000Z`);
  const fields = { previousHash, actorKind: "system" as const, actorId: null, eventType, entityType: "source", entityId: String(id), payload: { runId: id }, createdAt: createdAt.toISOString() };
  return { id, ...fields, eventHash: hashAuditEvent(fields), createdAt };
}

describe("audit integrity chain", () => {
  it("accepts a valid ordered append-only chain", () => {
    const first = makeRecord(1, null, "ingestion.started");
    const second = makeRecord(2, first.eventHash, "ingestion.completed");
    expect(verifyAuditRecords([first, second])).toEqual({ valid: true, checked: 2 });
  });

  it("detects a tampered payload", () => {
    const first = makeRecord(1, null, "ingestion.started");
    const second = makeRecord(2, first.eventHash, "ingestion.completed");
    second.payload = { runId: 999 };
    expect(verifyAuditRecords([first, second])).toEqual({ valid: false, checked: 2, brokenAt: 2 });
  });
});
