import { parse as parseCookie } from "cookie";
import { z } from "zod";
import { COOKIE_NAME } from "../../shared/const";
import {
  getDashboardCounts,
  getThreat,
  listAuditEvents,
  listIntelligenceSources,
  listMapObservations,
  listThreats,
  updateIntelligenceSource,
} from "../db";
import { createHeartbeatJob, updateHeartbeatJob } from "../_core/heartbeat";
import { appendAuditEvent, verifyAuditChain } from "../intelligence/audit";
import { generateDailyDigest, generateThreatBrief, ingestAllSources, ingestSource } from "../intelligence/service";
import { adminProcedure, router } from "../_core/trpc";

const intervalSchema = z.number().int().min(15).max(60);
const severitySchema = z.enum(["Critical", "High", "Medium", "Low"]);

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
});
