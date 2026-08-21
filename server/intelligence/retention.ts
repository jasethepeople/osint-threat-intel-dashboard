import { getRetentionPolicyByTaskUid, purgeExpiredThreats, updateRetentionPolicy } from "../db";
import { appendAuditEvent } from "./audit";
import type { IngestionActor } from "./types";

export async function executeRetentionPolicy(policy: { id: number; retentionDays: number; enabled: boolean }, actor: IngestionActor) {
  if (!policy.enabled) return { policyId: policy.id, skipped: "disabled" as const, purgedCount: 0 };
  const batchId = randomUUID();
  const result = await purgeExpiredThreats(policy.retentionDays, policy.id, batchId);
  await updateRetentionPolicy(policy.id, { lastRunAt: new Date(), lastPurgedCount: result.purgedCount });
  await appendAuditEvent({ actor, eventType: "retention.completed", entityType: "retention-policy", entityId: String(policy.id), payload: { retentionDays: policy.retentionDays, purgedCount: result.purgedCount, archiveCount: result.purgedCount, batchId, cutoff: result.cutoff.toISOString(), auditEntriesRetained: true } });
  return { policyId: policy.id, purgedCount: result.purgedCount, batchId, cutoff: result.cutoff };
}

export async function runScheduledRetention(taskUid: string) {
  const policy = await getRetentionPolicyByTaskUid(taskUid);
  if (!policy) return { ok: true, skipped: "orphan" };
  return { ok: true, outcome: await executeRetentionPolicy(policy, { kind: "schedule", id: taskUid }) };
}
import { randomUUID } from "node:crypto";
