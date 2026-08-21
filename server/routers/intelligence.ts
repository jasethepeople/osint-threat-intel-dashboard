import { parse as parseCookie } from "cookie";
import { z } from "zod";
import { COOKIE_NAME } from "../../shared/const";
import {
  getDashboardCounts,
  getRetentionPolicy,
  getThreat,
  createAlertRoute,
  createWatchlist,
  createSavedTriageView,
  deleteAlertRoute,
  deleteWatchlist,
  deleteSavedTriageView,
  listAuditEvents,
  listAlertRoutes,
  listIntelligenceSources,
  listRetentionLifecycle,
  listMapObservations,
  listThreats,
  listWatchlists,
  listSavedTriageViews,
  updateAlertRoute,
  updateIntelligenceSource,
  updateWatchlist,
  previewRetentionPurge,
  updateRetentionPolicy,
  updateSavedTriageView,
} from "../db";
import { createHeartbeatJob, updateHeartbeatJob } from "../_core/heartbeat";
import { ENV } from "../_core/env";
import { appendAuditEvent, verifyAuditChain } from "../intelligence/audit";
import { generateDailyDigest, generateThreatBrief, ingestAllSources, ingestSource } from "../intelligence/service";
import { executeRetentionPolicy } from "../intelligence/retention";
import { adminProcedure, router } from "../_core/trpc";

const intervalSchema = z.number().int().min(15).max(60);
const severitySchema = z.enum(["Critical", "High", "Medium", "Low"]);
const alertChannelSchema = z.enum(["owner_in_app", "audit_only", "slack_webhook", "teams_webhook"]);
const stackTermsSchema = z.array(z.string().trim().min(1).max(80)).min(1).max(24);
const viewStackTermsSchema = z.array(z.string().trim().min(1).max(80)).max(24);
const viewSeveritiesSchema = z.array(severitySchema).min(1).max(4);
const retentionDaysSchema = z.number().int().min(30).max(730);

function cronForInterval(minutes: number): string {
  return `0 */${minutes} * * * *`;
}

function actor(ctx: { user: { openId: string } }) {
  return { kind: "user" as const, id: ctx.user.openId };
}

function sessionToken(ctx: { req: { headers: { cookie?: string } } }) {
  return parseCookie(ctx.req.headers.cookie ?? "")[COOKIE_NAME] ?? "";
}

export const intelligenceRouter = router({
  overview: adminProcedure.query(async () => ({ counts: await getDashboardCounts(), sources: await listIntelligenceSources() })),
  sources: adminProcedure.query(() => listIntelligenceSources()),
  threats: adminProcedure.input(z.object({ limit: z.number().int().min(1).max(250).default(100), severity: severitySchema.optional() })).query(({ input }) => listThreats(input.limit, input.severity)),
  threat: adminProcedure.input(z.object({ id: z.number().int().positive() })).query(({ input }) => getThreat(input.id)),
  mapObservations: adminProcedure.query(() => listMapObservations()),
  audit: adminProcedure.input(z.object({ limit: z.number().int().min(1).max(250).default(100) })).query(async ({ input }) => ({ events: await listAuditEvents(input.limit), integrity: await verifyAuditChain() })),
  runSource: adminProcedure.input(z.object({ sourceId: z.number().int().positive() })).mutation(async ({ ctx, input }) => {
    await appendAuditEvent({ actor: actor(ctx), eventType: "user.sync-source", entityType: "source", entityId: String(input.sourceId), payload: {} });
    return ingestSource(input.sourceId, actor(ctx));
  }),
  runAllSources: adminProcedure.mutation(async ({ ctx }) => {
    await appendAuditEvent({ actor: actor(ctx), eventType: "user.sync-all-sources", entityType: "source", payload: {} });
    return ingestAllSources(actor(ctx));
  }),
  configureSource: adminProcedure.input(z.object({ sourceId: z.number().int().positive(), enabled: z.boolean(), pollIntervalMinutes: intervalSchema })).mutation(async ({ ctx, input }) => {
    const sources = await listIntelligenceSources();
    const source = sources.find(candidate => candidate.id === input.sourceId);
    if (!source) throw new Error("Intelligence source not found");
    const token = sessionToken(ctx);
    let taskUid = source.scheduleCronTaskUid;
    if (taskUid) {
      await updateHeartbeatJob(taskUid, { cron: cronForInterval(input.pollIntervalMinutes), enable: input.enabled, description: `Sentinel Atlas polling for ${source.name}` }, token);
    } else if (input.enabled) {
      const created = await createHeartbeatJob({
        name: `sentinel-atlas-source-${source.id}`,
        cron: cronForInterval(input.pollIntervalMinutes),
        path: "/api/scheduled/intelligence-ingest",
        payload: { sourceId: source.id },
        description: `Sentinel Atlas polling for ${source.name}`,
      }, token);
      taskUid = created.taskUid;
    }
    await updateIntelligenceSource(source.id, { enabled: input.enabled, pollIntervalMinutes: input.pollIntervalMinutes, scheduleCronTaskUid: taskUid });
    await appendAuditEvent({ actor: actor(ctx), eventType: "source.configured", entityType: "source", entityId: String(source.id), payload: { enabled: input.enabled, pollIntervalMinutes: input.pollIntervalMinutes, scheduleCronTaskUid: taskUid ?? null } });
    return { taskUid };
  }),
  generateBrief: adminProcedure.input(z.object({ threatId: z.number().int().positive() })).mutation(({ ctx, input }) => generateThreatBrief(input.threatId, actor(ctx))),
  generateDailyDigest: adminProcedure.mutation(({ ctx }) => generateDailyDigest(actor(ctx))),
  watchlists: adminProcedure.query(() => listWatchlists()),
  createWatchlist: adminProcedure.input(z.object({ name: z.string().trim().min(2).max(120), stackTerms: stackTermsSchema, enabled: z.boolean().default(true) })).mutation(async ({ ctx, input }) => {
    const id = await createWatchlist({ ...input, stackTerms: Array.from(new Set(input.stackTerms.map(term => term.trim()))) });
    await appendAuditEvent({ actor: actor(ctx), eventType: "watchlist.created", entityType: "watchlist", entityId: String(id), payload: { name: input.name, stackTerms: input.stackTerms, enabled: input.enabled } });
    return { id };
  }),
  updateWatchlist: adminProcedure.input(z.object({ id: z.number().int().positive(), name: z.string().trim().min(2).max(120).optional(), stackTerms: stackTermsSchema.optional(), enabled: z.boolean().optional() })).mutation(async ({ ctx, input }) => {
    const { id, ...values } = input;
    await updateWatchlist(id, values);
    await appendAuditEvent({ actor: actor(ctx), eventType: "watchlist.updated", entityType: "watchlist", entityId: String(id), payload: values });
    return { id };
  }),
  deleteWatchlist: adminProcedure.input(z.object({ id: z.number().int().positive() })).mutation(async ({ ctx, input }) => {
    await deleteWatchlist(input.id);
    await appendAuditEvent({ actor: actor(ctx), eventType: "watchlist.deleted", entityType: "watchlist", entityId: String(input.id), payload: {} });
    return { id: input.id };
  }),
  alertRoutes: adminProcedure.query(() => listAlertRoutes()),
  createAlertRoute: adminProcedure.input(z.object({ name: z.string().trim().min(2).max(120), watchlistId: z.number().int().positive().nullable(), minSeverity: severitySchema, includeZeroDays: z.boolean(), includeKnownExploited: z.boolean(), channel: alertChannelSchema.default("owner_in_app"), enabled: z.boolean().default(true) })).mutation(async ({ ctx, input }) => {
    const id = await createAlertRoute(input);
    await appendAuditEvent({ actor: actor(ctx), eventType: "alert-route.created", entityType: "alert-route", entityId: String(id), payload: input });
    return { id };
  }),
  updateAlertRoute: adminProcedure.input(z.object({ id: z.number().int().positive(), name: z.string().trim().min(2).max(120).optional(), watchlistId: z.number().int().positive().nullable().optional(), minSeverity: severitySchema.optional(), includeZeroDays: z.boolean().optional(), includeKnownExploited: z.boolean().optional(), channel: alertChannelSchema.optional(), enabled: z.boolean().optional() })).mutation(async ({ ctx, input }) => {
    const { id, ...values } = input;
    await updateAlertRoute(id, values);
    await appendAuditEvent({ actor: actor(ctx), eventType: "alert-route.updated", entityType: "alert-route", entityId: String(id), payload: values });
    return { id };
  }),
  deleteAlertRoute: adminProcedure.input(z.object({ id: z.number().int().positive() })).mutation(async ({ ctx, input }) => {
    await deleteAlertRoute(input.id);
    await appendAuditEvent({ actor: actor(ctx), eventType: "alert-route.deleted", entityType: "alert-route", entityId: String(input.id), payload: {} });
    return { id: input.id };
  }),
  triageViews: adminProcedure.query(() => listSavedTriageViews()),
  createTriageView: adminProcedure.input(z.object({ name: z.string().trim().min(2).max(120), stackTerms: viewStackTermsSchema, severities: viewSeveritiesSchema, enabled: z.boolean().default(true) })).mutation(async ({ ctx, input }) => {
    const id = await createSavedTriageView({ ...input, stackTerms: Array.from(new Set(input.stackTerms.map(term => term.trim().toLowerCase()))), severities: Array.from(new Set(input.severities)) });
    await appendAuditEvent({ actor: actor(ctx), eventType: "triage-view.created", entityType: "triage-view", entityId: String(id), payload: input });
    return { id };
  }),
  updateTriageView: adminProcedure.input(z.object({ id: z.number().int().positive(), name: z.string().trim().min(2).max(120).optional(), stackTerms: viewStackTermsSchema.optional(), severities: viewSeveritiesSchema.optional(), enabled: z.boolean().optional() })).mutation(async ({ ctx, input }) => {
    const { id, ...values } = input;
    await updateSavedTriageView(id, values);
    await appendAuditEvent({ actor: actor(ctx), eventType: "triage-view.updated", entityType: "triage-view", entityId: String(id), payload: values });
    return { id };
  }),
  deleteTriageView: adminProcedure.input(z.object({ id: z.number().int().positive() })).mutation(async ({ ctx, input }) => {
    await deleteSavedTriageView(input.id);
    await appendAuditEvent({ actor: actor(ctx), eventType: "triage-view.deleted", entityType: "triage-view", entityId: String(input.id), payload: {} });
    return { id: input.id };
  }),
  retentionPolicy: adminProcedure.query(() => getRetentionPolicy()),
  retentionTimeline: adminProcedure.input(z.object({ limit: z.number().int().min(1).max(250).default(100) })).query(({ input }) => listRetentionLifecycle(input.limit)),
  retentionPreview: adminProcedure.input(z.object({ retentionDays: retentionDaysSchema.optional() })).query(async ({ input }) => {
    const policy = await getRetentionPolicy();
    if (!policy) throw new Error("Retention policy unavailable");
    return previewRetentionPurge(input.retentionDays ?? policy.retentionDays);
  }),
  configureRetention: adminProcedure.input(z.object({ retentionDays: retentionDaysSchema, enabled: z.boolean() })).mutation(async ({ ctx, input }) => {
    const policy = await getRetentionPolicy();
    if (!policy) throw new Error("Retention policy unavailable");
    const token = sessionToken(ctx);
    if (policy.scheduleCronTaskUid && !input.enabled) await updateHeartbeatJob(policy.scheduleCronTaskUid, { enable: false, description: "Sentinel Atlas nightly intelligence retention" }, token);
    await updateRetentionPolicy(policy.id, input);
    await appendAuditEvent({ actor: actor(ctx), eventType: "retention.configured", entityType: "retention-policy", entityId: String(policy.id), payload: input });
    return { id: policy.id };
  }),
  runRetention: adminProcedure.input(z.object({ confirmation: z.literal("PURGE") })).mutation(async ({ ctx }) => {
    const policy = await getRetentionPolicy();
    if (!policy) throw new Error("Retention policy unavailable");
    if (!policy.enabled) throw new Error("Enable the retention policy before running a purge");
    return executeRetentionPolicy(policy, actor(ctx));
  }),
  activateRetentionSchedule: adminProcedure.mutation(async ({ ctx }) => {
    if (!ENV.isProduction) throw new Error("Publish the dashboard before activating the nightly retention schedule.");
    const policy = await getRetentionPolicy();
    if (!policy) throw new Error("Retention policy unavailable");
    if (!policy.enabled) throw new Error("Enable the retention policy before activating its schedule.");
    const token = sessionToken(ctx);
    let taskUid = policy.scheduleCronTaskUid;
    if (taskUid) {
      await updateHeartbeatJob(taskUid, { cron: "0 0 3 * * *", enable: true, description: "Sentinel Atlas nightly intelligence retention" }, token);
    } else {
      const created = await createHeartbeatJob({ name: `sentinel-atlas-retention-${policy.id}`, cron: "0 0 3 * * *", path: "/api/scheduled/intelligence-retention", description: "Sentinel Atlas nightly intelligence retention" }, token);
      taskUid = created.taskUid;
      await updateRetentionPolicy(policy.id, { scheduleCronTaskUid: taskUid });
    }
    await appendAuditEvent({ actor: actor(ctx), eventType: "retention.schedule-activated", entityType: "retention-policy", entityId: String(policy.id), payload: { scheduleCronTaskUid: taskUid, cron: "0 0 3 * * *" } });
    return { taskUid };
  }),
});
