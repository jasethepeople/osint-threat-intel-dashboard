import { and, desc, eq, sql } from "drizzle-orm";
import { drizzle } from "drizzle-orm/mysql2";
import {
  auditEvents,
  geoObservations,
  ingestionRuns,
  intelligenceSources,
  InsertUser,
  threatAlertRoutes,
  threatItems,
  threatWatchlists,
  users,
} from "../drizzle/schema";
import { ENV } from "./_core/env";
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

export async function createAlertRoute(values: { name: string; watchlistId: number | null; minSeverity: "Critical" | "High" | "Medium" | "Low"; includeZeroDays: boolean; includeKnownExploited: boolean; channel: "owner_in_app" | "audit_only"; enabled: boolean }) {
  const db = await getDb();
  if (!db) throw new Error("Database unavailable");
  const result = await db.insert(threatAlertRoutes).values(values);
  return Number(result[0].insertId);
}

export async function updateAlertRoute(id: number, values: { name?: string; watchlistId?: number | null; minSeverity?: "Critical" | "High" | "Medium" | "Low"; includeZeroDays?: boolean; includeKnownExploited?: boolean; channel?: "owner_in_app" | "audit_only"; enabled?: boolean }) {
  const db = await getDb();
  if (!db) throw new Error("Database unavailable");
  await db.update(threatAlertRoutes).set({ ...values, updatedAt: new Date() }).where(eq(threatAlertRoutes.id, id));
}

export async function deleteAlertRoute(id: number) {
  const db = await getDb();
  if (!db) throw new Error("Database unavailable");
  await db.delete(threatAlertRoutes).where(eq(threatAlertRoutes.id, id));
}
