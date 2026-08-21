import { createHash } from "node:crypto";
import { asc, desc, eq } from "drizzle-orm";
import { auditEvents } from "../../drizzle/schema";
import { getDb } from "../db";
import type { IngestionActor } from "./types";

type AuditInput = {
  actor: IngestionActor;
  eventType: string;
  entityType: string;
  entityId?: string;
  payload: Record<string, unknown>;
};

export type AuditChainRecord = {
  id?: number;
  actorKind: "system" | "user" | "schedule";
  actorId: string | null;
  eventType: string;
  entityType: string;
  entityId: string | null;
  payload: Record<string, unknown>;
  previousHash: string | null;
  eventHash: string;
  createdAt: Date;
};

export function stableSerialize(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableSerialize).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.entries(value as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b)).map(([key, nested]) => `${JSON.stringify(key)}:${stableSerialize(nested)}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

export function hashAuditEvent(value: Record<string, unknown>): string {
  return createHash("sha256").update(stableSerialize(value)).digest("hex");
}

export function verifyAuditRecords(events: AuditChainRecord[]): { valid: boolean; checked: number; brokenAt?: number } {
  let previousHash: string | null = null;
  for (const event of events) {
    const expected = hashAuditEvent({ previousHash, actorKind: event.actorKind, actorId: event.actorId ?? null, eventType: event.eventType, entityType: event.entityType, entityId: event.entityId ?? null, payload: event.payload, createdAt: event.createdAt.toISOString() });
    if (event.previousHash !== previousHash || event.eventHash !== expected) return { valid: false, checked: events.length, brokenAt: event.id };
    previousHash = event.eventHash;
  }
  return { valid: true, checked: events.length };
}

function eventHashFields(event: Omit<AuditChainRecord, "eventHash" | "previousHash">, previousHash: string | null) {
  return { previousHash, actorKind: event.actorKind, actorId: event.actorId ?? null, eventType: event.eventType, entityType: event.entityType, entityId: event.entityId ?? null, payload: event.payload, createdAt: event.createdAt.toISOString() };
}

export async function appendAuditEvent(input: AuditInput): Promise<void> {
  const db = await getDb();
  if (!db) throw new Error("Database unavailable");
  const previous = await db.select({ eventHash: auditEvents.eventHash }).from(auditEvents).orderBy(desc(auditEvents.id)).limit(1);
  // MySQL TIMESTAMP uses second precision by default; use the same precision in the hashed payload.
  const createdAt = new Date(Math.floor(Date.now() / 1000) * 1000);
  const previousHash = previous[0]?.eventHash ?? null;
  const eventHash = hashAuditEvent({
    previousHash,
    actorKind: input.actor.kind,
    actorId: input.actor.id ?? null,
    eventType: input.eventType,
    entityType: input.entityType,
    entityId: input.entityId ?? null,
    payload: input.payload,
    createdAt: createdAt.toISOString(),
  });
  await db.insert(auditEvents).values({
    actorKind: input.actor.kind,
    actorId: input.actor.id,
    eventType: input.eventType,
    entityType: input.entityType,
    entityId: input.entityId,
    payload: input.payload,
    previousHash,
    eventHash,
    createdAt,
  });
}

export async function verifyAuditChain(): Promise<{ valid: boolean; checked: number; brokenAt?: number }> {
  const db = await getDb();
  if (!db) return { valid: false, checked: 0 };
  const events = await db.select().from(auditEvents).orderBy(asc(auditEvents.id));
  return verifyAuditRecords(events.map(event => ({ ...event, actorId: event.actorId ?? null, entityId: event.entityId ?? null, previousHash: event.previousHash ?? null })));
}

/** Server-only maintenance helper for entries created before timestamp canonicalization. */
export async function resealAuditChain(): Promise<{ resealed: number }> {
  const db = await getDb();
  if (!db) throw new Error("Database unavailable");
  const events = await db.select().from(auditEvents).orderBy(asc(auditEvents.id));
  let previousHash: string | null = null;
  for (const event of events) {
    const canonical = { ...event, actorId: event.actorId ?? null, entityId: event.entityId ?? null };
    const eventHash = hashAuditEvent(eventHashFields(canonical, previousHash));
    await db.update(auditEvents).set({ previousHash, eventHash }).where(eq(auditEvents.id, event.id));
    previousHash = eventHash;
  }
  return { resealed: events.length };
}
