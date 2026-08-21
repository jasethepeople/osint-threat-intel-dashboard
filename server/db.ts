import { and, desc, eq, inArray, lt, sql } from "drizzle-orm";
import { drizzle } from "drizzle-orm/mysql2";
import {
  auditEvents,
  geoObservations,
  ingestionRuns,
  intelligenceSources,
  intelligenceRetentionPolicies,
  InsertUser,
  retentionArchiveManifests,
  savedTriageViews,
  threatAlertRoutes,
  threatItems,
  threatWatchlists,
  users,
} from "../drizzle/schema";
import { ENV } from "./_core/env";
import { retentionCutoff } from "../shared/retention";
import { DEFAULT_SOURCES } from "./intelligence/sources";
import type { EnrichedThreat, IngestionActor } from "./intelligence/types";

let _db: ReturnType<typeof drizzle> | null = null;

export async function getDb() {
  if (!_db && process.env.DATABASE_URL) {
    try {
      _db = drizzle(process.env.DATABASE_URL);
    } catch (error) {
      console.warn("[Database] Failed to connect:", error);
      _db = null;
    }
  }
  return _db;
}

export async function upsertUser(user: InsertUser): Promise<void> {
  if (!user.openId) throw new Error("User openId is required for upsert");
  const db = await getDb();
  if (!db) return;
  const values: InsertUser = { openId: user.openId, lastSignedIn: user.lastSignedIn ?? new Date() };
  const updateSet: Record<string, unknown> = { lastSignedIn: values.lastSignedIn };
  for (const field of ["name", "email", "loginMethod"] as const) {
    if (user[field] !== undefined) {
      values[field] = user[field] ?? null;
      updateSet[field] = user[field] ?? null;
    }
  }
  values.role = user.role ?? (user.openId === ENV.ownerOpenId ? "admin" : "user");
  updateSet.role = values.role;
  await db.insert(users).values(values).onDuplicateKeyUpdate({ set: updateSet });
}

export async function getUserByOpenId(openId: string) {
  const db = await getDb();
  if (!db) return undefined;
  return (await db.select().from(users).where(eq(users.openId, openId)).limit(1))[0];
}

export async function ensureDefaultSources() {
  const db = await getDb();
  if (!db) throw new Error("Database unavailable");
  const legacyCisa = await db.select({ id: intelligenceSources.id }).from(intelligenceSources).where(eq(intelligenceSources.sourceKey, "cisa-advisories-rss")).limit(1);
  if (legacyCisa[0]) {
    await db.update(intelligenceSources).set({ sourceKey: "securityweek-rss", name: "SecurityWeek RSS", endpoint: "https://www.securityweek.com/feed/", kind: "rss", lastError: null, updatedAt: new Date() }).where(eq(intelligenceSources.id, legacyCisa[0].id));
  }
  for (const source of DEFAULT_SOURCES) {
    await db.insert(intelligenceSources).values({ ...source, pollIntervalMinutes: 30 }).onDuplicateKeyUpdate({ set: { name: source.name, endpoint: source.endpoint, updatedAt: new Date() } });
  }
}

export async function listIntelligenceSources() {
  await ensureDefaultSources();
  const db = await getDb();
  if (!db) return [];
  return db.select().from(intelligenceSources).orderBy(intelligenceSources.id);
}

export async function getIntelligenceSource(sourceId: number) {
  const db = await getDb();
  if (!db) return undefined;
  return (await db.select().from(intelligenceSources).where(eq(intelligenceSources.id, sourceId)).limit(1))[0];
}

export async function getIntelligenceSourceByTaskUid(taskUid: string) {
  const db = await getDb();
  if (!db) return undefined;
  return (await db.select().from(intelligenceSources).where(eq(intelligenceSources.scheduleCronTaskUid, taskUid)).limit(1))[0];
}

export async function updateIntelligenceSource(sourceId: number, values: Partial<typeof intelligenceSources.$inferInsert>) {
  const db = await getDb();
  if (!db) throw new Error("Database unavailable");
  await db.update(intelligenceSources).set({ ...values, updatedAt: new Date() }).where(eq(intelligenceSources.id, sourceId));
}

export async function createIngestionRun(sourceId: number, actor: IngestionActor) {
  const db = await getDb();
  if (!db) throw new Error("Database unavailable");
  const result = await db.insert(ingestionRuns).values({ sourceId, requestedBy: actor.kind, status: "running" });
  return result[0].insertId;
}

export async function finishIngestionRun(runId: number, values: { status: "completed" | "failed" | "skipped"; itemsFetched?: number; itemsCreated?: number; itemsUpdated?: number; errorMessage?: string }) {
  const db = await getDb();
  if (!db) throw new Error("Database unavailable");
  await db.update(ingestionRuns).set({ ...values, completedAt: new Date() }).where(eq(ingestionRuns.id, runId));
}

export async function persistThreat(sourceId: number, threat: EnrichedThreat): Promise<{ id: number; created: boolean }> {
  const db = await getDb();
  if (!db) throw new Error("Database unavailable");
  const existing = await db.select({ id: threatItems.id }).from(threatItems).where(and(eq(threatItems.sourceId, sourceId), eq(threatItems.sourceExternalId, threat.sourceExternalId))).limit(1);
  const values = {
    cveId: threat.cveId,
    ghsaId: threat.ghsaId,
    title: threat.title,
    description: threat.description,
    affectedStack: threat.affectedStack,
    severity: threat.severity,
    cvssScore: threat.cvssScore === undefined ? null : threat.cvssScore.toFixed(1),
    sourceUrl: threat.sourceUrl,
    sourcePublishedAt: threat.sourcePublishedAt,
    sourceUpdatedAt: threat.sourceUpdatedAt,
    extractedGeoTags: threat.extractedGeoTags,
    zeroDayFlag: threat.zeroDayFlag,
    knownExploitedFlag: threat.knownExploitedFlag,
    rawContentHash: threat.rawContentHash,
    ingestionTimestamp: new Date(),
    updatedAt: new Date(),
  };
  if (existing[0]) {
    await db.update(threatItems).set(values).where(eq(threatItems.id, existing[0].id));
    return { id: existing[0].id, created: false };
  }
  const inserted = await db.insert(threatItems).values({ sourceId, sourceExternalId: threat.sourceExternalId, ...values });
  return { id: Number(inserted[0].insertId), created: true };
}

export async function storeGeoObservations(threatItemId: number, observations: EnrichedThreat["geoObservations"]) {
  const db = await getDb();
  if (!db) throw new Error("Database unavailable");
  await db.delete(geoObservations).where(eq(geoObservations.threatItemId, threatItemId));
  if (!observations.length) return;
  await db.insert(geoObservations).values(observations.map(observation => ({
    threatItemId,
    label: observation.label,
    countryCode: observation.countryCode,
    latitude: observation.latitude === undefined ? null : observation.latitude.toFixed(6),
    longitude: observation.longitude === undefined ? null : observation.longitude.toFixed(6),
    confidence: observation.confidence.toFixed(2),
    extractionMethod: observation.extractionMethod,
  })));
}

export async function listThreats(limit = 100, severity?: (typeof threatItems.$inferSelect)["severity"]) {
  const db = await getDb();
  if (!db) return [];
  const query = db.select().from(threatItems).orderBy(desc(threatItems.ingestionTimestamp)).limit(limit);
  return severity ? query.where(eq(threatItems.severity, severity)) : query;
}

export async function getThreat(threatId: number) {
  const db = await getDb();
  if (!db) return undefined;
  return (await db.select().from(threatItems).where(eq(threatItems.id, threatId)).limit(1))[0];
}

export async function updateThreatBrief(threatId: number, brief: string, model: string) {
  const db = await getDb();
  if (!db) throw new Error("Database unavailable");
  await db.update(threatItems).set({ analystBrief: brief, analystBriefModel: model, analystBriefGeneratedAt: new Date(), updatedAt: new Date() }).where(eq(threatItems.id, threatId));
}

export async function listMapObservations() {
  const db = await getDb();
  if (!db) return [];
  return db.select({
    id: geoObservations.id,
    label: geoObservations.label,
    countryCode: geoObservations.countryCode,
    latitude: geoObservations.latitude,
    longitude: geoObservations.longitude,
    confidence: geoObservations.confidence,
    threatId: threatItems.id,
    title: threatItems.title,
    cveId: threatItems.cveId,
    severity: threatItems.severity,
    sourceUrl: threatItems.sourceUrl,
  }).from(geoObservations).innerJoin(threatItems, eq(geoObservations.threatItemId, threatItems.id)).orderBy(desc(threatItems.ingestionTimestamp));
}

export async function listAuditEvents(limit = 100) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(auditEvents).orderBy(desc(auditEvents.id)).limit(limit);
}

export async function listRetentionLifecycle(limit = 100) {
  const db = await getDb();
  if (!db) return { auditEvents: [], archivedRecords: [] };
  const [events, records] = await Promise.all([
    db.select().from(auditEvents).where(sql`${auditEvents.eventType} like 'retention.%'`).orderBy(desc(auditEvents.id)).limit(limit),
    db.select().from(retentionArchiveManifests).orderBy(desc(retentionArchiveManifests.archivedAt)).limit(limit),
  ]);
  return { auditEvents: events, archivedRecords: records };
}

export async function getDashboardCounts() {
  const db = await getDb();
  if (!db) return { Critical: 0, High: 0, Medium: 0, Low: 0, total: 0 };
  const rows = await db.select({ severity: threatItems.severity, count: sql<number>`count(*)` }).from(threatItems).groupBy(threatItems.severity);
  const counts = { Critical: 0, High: 0, Medium: 0, Low: 0, total: 0 };
  for (const row of rows) {
    const count = Number(row.count);
    counts[row.severity] = count;
    counts.total += count;
  }
  return counts;
}

export async function listWatchlists() {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(threatWatchlists).orderBy(desc(threatWatchlists.updatedAt));
}

export async function listEnabledWatchlists() {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(threatWatchlists).where(eq(threatWatchlists.enabled, true));
}

export async function createWatchlist(values: { name: string; stackTerms: string[]; enabled: boolean }) {
  const db = await getDb();
  if (!db) throw new Error("Database unavailable");
  const result = await db.insert(threatWatchlists).values(values);
  return Number(result[0].insertId);
}

export async function updateWatchlist(id: number, values: { name?: string; stackTerms?: string[]; enabled?: boolean }) {
  const db = await getDb();
  if (!db) throw new Error("Database unavailable");
  await db.update(threatWatchlists).set({ ...values, updatedAt: new Date() }).where(eq(threatWatchlists.id, id));
}

export async function deleteWatchlist(id: number) {
  const db = await getDb();
  if (!db) throw new Error("Database unavailable");
  // Keep rules valid after a watchlist removal by turning them into global rules.
  await db.update(threatAlertRoutes).set({ watchlistId: null, updatedAt: new Date() }).where(eq(threatAlertRoutes.watchlistId, id));
  await db.delete(threatWatchlists).where(eq(threatWatchlists.id, id));
}

export async function listAlertRoutes() {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(threatAlertRoutes).orderBy(desc(threatAlertRoutes.updatedAt));
}

export async function listEnabledAlertRoutes() {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(threatAlertRoutes).where(eq(threatAlertRoutes.enabled, true));
}

export async function createAlertRoute(values: { name: string; watchlistId: number | null; minSeverity: "Critical" | "High" | "Medium" | "Low"; includeZeroDays: boolean; includeKnownExploited: boolean; channel: "owner_in_app" | "audit_only" | "slack_webhook" | "teams_webhook"; enabled: boolean }) {
  const db = await getDb();
  if (!db) throw new Error("Database unavailable");
  const result = await db.insert(threatAlertRoutes).values(values);
  return Number(result[0].insertId);
}

export async function updateAlertRoute(id: number, values: { name?: string; watchlistId?: number | null; minSeverity?: "Critical" | "High" | "Medium" | "Low"; includeZeroDays?: boolean; includeKnownExploited?: boolean; channel?: "owner_in_app" | "audit_only" | "slack_webhook" | "teams_webhook"; enabled?: boolean }) {
  const db = await getDb();
  if (!db) throw new Error("Database unavailable");
  await db.update(threatAlertRoutes).set({ ...values, updatedAt: new Date() }).where(eq(threatAlertRoutes.id, id));
}

export async function deleteAlertRoute(id: number) {
  const db = await getDb();
  if (!db) throw new Error("Database unavailable");
  await db.delete(threatAlertRoutes).where(eq(threatAlertRoutes.id, id));
}

export async function listSavedTriageViews() {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(savedTriageViews).orderBy(desc(savedTriageViews.updatedAt));
}

export async function createSavedTriageView(values: { name: string; stackTerms: string[]; severities: ("Critical" | "High" | "Medium" | "Low")[]; enabled: boolean }) {
  const db = await getDb();
  if (!db) throw new Error("Database unavailable");
  const result = await db.insert(savedTriageViews).values(values);
  return Number(result[0].insertId);
}

export async function updateSavedTriageView(id: number, values: { name?: string; stackTerms?: string[]; severities?: ("Critical" | "High" | "Medium" | "Low")[]; enabled?: boolean }) {
  const db = await getDb();
  if (!db) throw new Error("Database unavailable");
  await db.update(savedTriageViews).set({ ...values, updatedAt: new Date() }).where(eq(savedTriageViews.id, id));
}

export async function deleteSavedTriageView(id: number) {
  const db = await getDb();
  if (!db) throw new Error("Database unavailable");
  await db.delete(savedTriageViews).where(eq(savedTriageViews.id, id));
}

export async function getRetentionPolicy() {
  const db = await getDb();
  if (!db) return undefined;
  let policy = (await db.select().from(intelligenceRetentionPolicies).orderBy(intelligenceRetentionPolicies.id).limit(1))[0];
  if (!policy) {
    const result = await db.insert(intelligenceRetentionPolicies).values({ retentionDays: 90, enabled: false, lastPurgedCount: 0 });
    policy = (await db.select().from(intelligenceRetentionPolicies).where(eq(intelligenceRetentionPolicies.id, Number(result[0].insertId))).limit(1))[0];
  }
  return policy;
}

export async function getRetentionPolicyByTaskUid(taskUid: string) {
  const db = await getDb();
  if (!db) return undefined;
  return (await db.select().from(intelligenceRetentionPolicies).where(eq(intelligenceRetentionPolicies.scheduleCronTaskUid, taskUid)).limit(1))[0];
}

export async function updateRetentionPolicy(id: number, values: { retentionDays?: number; enabled?: boolean; scheduleCronTaskUid?: string | null; lastRunAt?: Date; lastPurgedCount?: number }) {
  const db = await getDb();
  if (!db) throw new Error("Database unavailable");
  await db.update(intelligenceRetentionPolicies).set({ ...values, updatedAt: new Date() }).where(eq(intelligenceRetentionPolicies.id, id));
}

export async function previewRetentionPurge(retentionDays: number) {
  const db = await getDb();
  if (!db) throw new Error("Database unavailable");
  const cutoff = retentionCutoff(retentionDays);
  const rows = await db.select({ count: sql<number>`count(*)`, oldest: sql<Date | null>`min(${threatItems.ingestionTimestamp})` }).from(threatItems).where(lt(threatItems.ingestionTimestamp, cutoff));
  return { cutoff, candidateCount: Number(rows[0]?.count ?? 0), oldestIngestionAt: rows[0]?.oldest ?? null };
}

/** Archives a minimal manifest, then deletes aged threat and map records. Append-only audit entries remain immutable. */
export async function purgeExpiredThreats(retentionDays: number, retentionPolicyId: number, batchId: string) {
  const db = await getDb();
  if (!db) throw new Error("Database unavailable");
  const cutoff = retentionCutoff(retentionDays);
  const rows = await db.select({ id: threatItems.id, cveId: threatItems.cveId, ghsaId: threatItems.ghsaId, title: threatItems.title, severity: threatItems.severity, affectedStack: threatItems.affectedStack, sourceUrl: threatItems.sourceUrl, ingestionTimestamp: threatItems.ingestionTimestamp }).from(threatItems).where(lt(threatItems.ingestionTimestamp, cutoff));
  const ids = rows.map(row => row.id);
  if (!ids.length) return { cutoff, purgedCount: 0 };
  const archivedAt = new Date();
  await db.insert(retentionArchiveManifests).values(rows.map(row => ({ retentionPolicyId, batchId, originalThreatId: row.id, cveId: row.cveId, ghsaId: row.ghsaId, title: row.title, severity: row.severity, affectedStack: row.affectedStack, sourceUrl: row.sourceUrl, originalIngestionAt: row.ingestionTimestamp, archivedAt })));
  await db.delete(geoObservations).where(inArray(geoObservations.threatItemId, ids));
  await db.delete(threatItems).where(inArray(threatItems.id, ids));
  return { cutoff, purgedCount: ids.length, batchId };
}
