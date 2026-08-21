import {
  boolean,
  decimal,
  index,
  int,
  json,
  mysqlEnum,
  mysqlTable,
  text,
  timestamp,
  uniqueIndex,
  varchar,
} from "drizzle-orm/mysql-core";

/** Core user table backing the Manus OAuth flow. */
export const users = mysqlTable("users", {
  id: int("id").autoincrement().primaryKey(),
  openId: varchar("openId", { length: 64 }).notNull().unique(),
  name: text("name"),
  email: varchar("email", { length: 320 }),
  loginMethod: varchar("loginMethod", { length: 64 }),
  role: mysqlEnum("role", ["user", "admin"]).default("user").notNull(),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
  lastSignedIn: timestamp("lastSignedIn").defaultNow().notNull(),
});

export const sourceKinds = ["nvd", "github", "rss"] as const;
export const severityTiers = ["Critical", "High", "Medium", "Low"] as const;
export const auditActorKinds = ["system", "user", "schedule"] as const;
export const alertChannels = ["owner_in_app", "audit_only", "slack_webhook", "teams_webhook"] as const;

/** Configurable, source-specific polling state. */
export const intelligenceSources = mysqlTable(
  "intelligence_sources",
  {
    id: int("id").autoincrement().primaryKey(),
    sourceKey: varchar("sourceKey", { length: 80 }).notNull(),
    name: varchar("name", { length: 160 }).notNull(),
    kind: mysqlEnum("kind", sourceKinds).notNull(),
    endpoint: text("endpoint").notNull(),
    enabled: boolean("enabled").default(true).notNull(),
    pollIntervalMinutes: int("pollIntervalMinutes").default(30).notNull(),
    scheduleCronTaskUid: varchar("scheduleCronTaskUid", { length: 65 }),
    lastCursor: text("lastCursor"),
    lastSuccessAt: timestamp("lastSuccessAt"),
    lastError: text("lastError"),
    createdAt: timestamp("createdAt").defaultNow().notNull(),
    updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
  },
  table => [
    uniqueIndex("intelligence_sources_key_unique").on(table.sourceKey),
    index("intelligence_sources_schedule_idx").on(table.scheduleCronTaskUid),
  ]
);

/** Each source poll is tracked for operational transparency and idempotency. */
export const ingestionRuns = mysqlTable(
  "ingestion_runs",
  {
    id: int("id").autoincrement().primaryKey(),
    sourceId: int("sourceId").notNull(),
    requestedBy: mysqlEnum("requestedBy", auditActorKinds).notNull(),
    status: mysqlEnum("status", ["running", "completed", "failed", "skipped"]).notNull(),
    itemsFetched: int("itemsFetched").default(0).notNull(),
    itemsCreated: int("itemsCreated").default(0).notNull(),
    itemsUpdated: int("itemsUpdated").default(0).notNull(),
    startedAt: timestamp("startedAt").defaultNow().notNull(),
    completedAt: timestamp("completedAt"),
    errorMessage: text("errorMessage"),
  },
  table => [index("ingestion_runs_source_started_idx").on(table.sourceId, table.startedAt)]
);

/** Normalized, source-attributed advisory or news-derived threat item. */
export const threatItems = mysqlTable(
  "threat_items",
  {
    id: int("id").autoincrement().primaryKey(),
    sourceId: int("sourceId").notNull(),
    sourceExternalId: varchar("sourceExternalId", { length: 255 }).notNull(),
    cveId: varchar("cveId", { length: 64 }),
    ghsaId: varchar("ghsaId", { length: 64 }),
    title: text("title").notNull(),
    description: text("description").notNull(),
    affectedStack: json("affectedStack").$type<string[]>().notNull(),
    severity: mysqlEnum("severity", severityTiers).default("Low").notNull(),
    cvssScore: decimal("cvssScore", { precision: 4, scale: 1 }),
    sourceUrl: text("sourceUrl").notNull(),
    sourcePublishedAt: timestamp("sourcePublishedAt"),
    sourceUpdatedAt: timestamp("sourceUpdatedAt"),
    extractedGeoTags: json("extractedGeoTags").$type<string[]>().notNull(),
    zeroDayFlag: boolean("zeroDayFlag").default(false).notNull(),
    knownExploitedFlag: boolean("knownExploitedFlag").default(false).notNull(),
    rawContentHash: varchar("rawContentHash", { length: 64 }).notNull(),
    analystBrief: text("analystBrief"),
    analystBriefModel: varchar("analystBriefModel", { length: 80 }),
    analystBriefGeneratedAt: timestamp("analystBriefGeneratedAt"),
    ingestionTimestamp: timestamp("ingestionTimestamp").defaultNow().notNull(),
    createdAt: timestamp("createdAt").defaultNow().notNull(),
    updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
  },
  table => [
    uniqueIndex("threat_items_source_external_unique").on(table.sourceId, table.sourceExternalId),
    index("threat_items_severity_ingested_idx").on(table.severity, table.ingestionTimestamp),
    index("threat_items_cve_idx").on(table.cveId),
  ]
);

/** Extracted geographic observations used to preserve map provenance and confidence. */
export const geoObservations = mysqlTable(
  "geo_observations",
  {
    id: int("id").autoincrement().primaryKey(),
    threatItemId: int("threatItemId").notNull(),
    label: varchar("label", { length: 160 }).notNull(),
    countryCode: varchar("countryCode", { length: 2 }),
    latitude: decimal("latitude", { precision: 9, scale: 6 }),
    longitude: decimal("longitude", { precision: 9, scale: 6 }),
    confidence: decimal("confidence", { precision: 3, scale: 2 }).notNull(),
    extractionMethod: varchar("extractionMethod", { length: 48 }).notNull(),
    createdAt: timestamp("createdAt").defaultNow().notNull(),
  },
  table => [index("geo_observations_threat_idx").on(table.threatItemId)]
);

/** Organization-defined software and platform terms to monitor in normalized threats. */
export const threatWatchlists = mysqlTable(
  "threat_watchlists",
  {
    id: int("id").autoincrement().primaryKey(),
    name: varchar("name", { length: 120 }).notNull(),
    stackTerms: json("stackTerms").$type<string[]>().notNull(),
    enabled: boolean("enabled").default(true).notNull(),
    createdAt: timestamp("createdAt").defaultNow().notNull(),
    updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
  },
  table => [index("threat_watchlists_enabled_idx").on(table.enabled)]
);

/** Rule-driven delivery controls for the project owner notification channel. */
export const threatAlertRoutes = mysqlTable(
  "threat_alert_routes",
  {
    id: int("id").autoincrement().primaryKey(),
    name: varchar("name", { length: 120 }).notNull(),
    watchlistId: int("watchlistId"),
    minSeverity: mysqlEnum("minSeverity", severityTiers).default("Critical").notNull(),
    includeZeroDays: boolean("includeZeroDays").default(true).notNull(),
    includeKnownExploited: boolean("includeKnownExploited").default(false).notNull(),
    channel: mysqlEnum("channel", alertChannels).default("owner_in_app").notNull(),
    enabled: boolean("enabled").default(true).notNull(),
    createdAt: timestamp("createdAt").defaultNow().notNull(),
    updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
  },
  table => [index("threat_alert_routes_enabled_idx").on(table.enabled), index("threat_alert_routes_watchlist_idx").on(table.watchlistId)]
);

/** Reusable business-unit triage scopes over retained, source-attributed threat records. */
export const savedTriageViews = mysqlTable(
  "saved_triage_views",
  {
    id: int("id").autoincrement().primaryKey(),
    name: varchar("name", { length: 120 }).notNull(),
    stackTerms: json("stackTerms").$type<string[]>().notNull(),
    severities: json("severities").$type<(typeof severityTiers)[number][]>().notNull(),
    enabled: boolean("enabled").default(true).notNull(),
    createdAt: timestamp("createdAt").defaultNow().notNull(),
    updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
  },
  table => [index("saved_triage_views_enabled_idx").on(table.enabled)]
);

/** One explicit retention policy controls aging intelligence cleanup; audit events remain immutable. */
export const intelligenceRetentionPolicies = mysqlTable(
  "intelligence_retention_policies",
  {
    id: int("id").autoincrement().primaryKey(),
    retentionDays: int("retentionDays").default(90).notNull(),
    enabled: boolean("enabled").default(false).notNull(),
    scheduleCronTaskUid: varchar("scheduleCronTaskUid", { length: 65 }),
    lastRunAt: timestamp("lastRunAt"),
    lastPurgedCount: int("lastPurgedCount").default(0).notNull(),
    createdAt: timestamp("createdAt").defaultNow().notNull(),
    updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
  },
  table => [index("intelligence_retention_policy_schedule_idx").on(table.scheduleCronTaskUid)]
);

/** Minimal immutable manifest retained for timeline evidence after a threat record is purged. */
export const retentionArchiveManifests = mysqlTable(
  "retention_archive_manifests",
  {
    id: int("id").autoincrement().primaryKey(),
    retentionPolicyId: int("retentionPolicyId").notNull(),
    batchId: varchar("batchId", { length: 36 }).notNull(),
    originalThreatId: int("originalThreatId").notNull(),
    cveId: varchar("cveId", { length: 64 }),
    ghsaId: varchar("ghsaId", { length: 64 }),
    title: text("title").notNull(),
    severity: mysqlEnum("severity", severityTiers).notNull(),
    affectedStack: json("affectedStack").$type<string[]>().notNull(),
    sourceUrl: text("sourceUrl").notNull(),
    originalIngestionAt: timestamp("originalIngestionAt").notNull(),
    archivedAt: timestamp("archivedAt").defaultNow().notNull(),
  },
  table => [index("retention_archive_batch_idx").on(table.batchId), index("retention_archive_archived_idx").on(table.archivedAt)]
);

/** Append-only hash-chain records. Database helpers only append; integrity can be checked at read time. */
export const auditEvents = mysqlTable(
  "audit_events",
  {
    id: int("id").autoincrement().primaryKey(),
    actorKind: mysqlEnum("actorKind", auditActorKinds).notNull(),
    actorId: varchar("actorId", { length: 128 }),
    eventType: varchar("eventType", { length: 100 }).notNull(),
    entityType: varchar("entityType", { length: 80 }).notNull(),
    entityId: varchar("entityId", { length: 128 }),
    payload: json("payload").$type<Record<string, unknown>>().notNull(),
    previousHash: varchar("previousHash", { length: 64 }),
    eventHash: varchar("eventHash", { length: 64 }).notNull(),
    createdAt: timestamp("createdAt").defaultNow().notNull(),
  },
  table => [
    uniqueIndex("audit_events_hash_unique").on(table.eventHash),
    index("audit_events_created_idx").on(table.createdAt),
  ]
);

export type User = typeof users.$inferSelect;
export type InsertUser = typeof users.$inferInsert;
export type IntelligenceSource = typeof intelligenceSources.$inferSelect;
export type ThreatItem = typeof threatItems.$inferSelect;
export type AuditEvent = typeof auditEvents.$inferSelect;
export type ThreatWatchlist = typeof threatWatchlists.$inferSelect;
export type ThreatAlertRoute = typeof threatAlertRoutes.$inferSelect;
export type SavedTriageView = typeof savedTriageViews.$inferSelect;
export type IntelligenceRetentionPolicy = typeof intelligenceRetentionPolicies.$inferSelect;
export type RetentionArchiveManifest = typeof retentionArchiveManifests.$inferSelect;
