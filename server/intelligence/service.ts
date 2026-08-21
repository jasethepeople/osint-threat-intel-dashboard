import { eq } from "drizzle-orm";
import { threatItems } from "../../drizzle/schema";
import {
  createIngestionRun,
  finishIngestionRun,
  getIntelligenceSource,
  getIntelligenceSourceByTaskUid,
  getThreat,
  persistThreat,
  storeGeoObservations,
  updateIntelligenceSource,
  updateThreatBrief,
} from "../db";
import { invokeLLM } from "../_core/llm";
import { notifyOwner } from "../_core/notification";
import { appendAuditEvent } from "./audit";
import { enrichThreat } from "./extraction";
import { fetchSourceThreats } from "./sources";
import type { IngestionActor } from "./types";

const BRIEF_MODEL = "gpt-5-mini";

export async function ingestSource(sourceId: number, actor: IngestionActor) {
  const source = await getIntelligenceSource(sourceId);
  if (!source) throw new Error("Intelligence source not found");
  if (!source.enabled) return { sourceId, status: "skipped" as const, itemsFetched: 0, itemsCreated: 0, itemsUpdated: 0 };

  const runId = await createIngestionRun(source.id, actor);
  await appendAuditEvent({ actor, eventType: "ingestion.started", entityType: "source", entityId: String(source.id), payload: { sourceKey: source.sourceKey, runId } });
  try {
    const items = await fetchSourceThreats(source);
    let itemsCreated = 0;
    let itemsUpdated = 0;
    for (const item of items) {
      const enriched = enrichThreat(item);
      const stored = await persistThreat(source.id, enriched);
      if (stored.created) itemsCreated += 1;
      else itemsUpdated += 1;
      await storeGeoObservations(stored.id, enriched.geoObservations);
      await appendAuditEvent({
        actor,
        eventType: "threat.extracted",
        entityType: "threat",
        entityId: String(stored.id),
        payload: {
          sourceId: source.id,
          sourceExternalId: enriched.sourceExternalId,
          cveId: enriched.cveId ?? null,
          severity: enriched.severity,
          stackCount: enriched.affectedStack.length,
          geoTags: enriched.extractedGeoTags,
          created: stored.created,
        },
      });
      if (stored.created && (enriched.severity === "Critical" || enriched.zeroDayFlag)) {
        const delivered = await notifyOwner({
          title: enriched.zeroDayFlag ? "Zero-day indicator detected" : "Critical threat detected",
          content: `${enriched.cveId ?? enriched.title} · ${source.name} · ${enriched.severity}`,
        });
        await appendAuditEvent({
          actor: { kind: "system" },
          eventType: "notification.critical-threat",
          entityType: "threat",
          entityId: String(stored.id),
          payload: { delivered, zeroDayFlag: enriched.zeroDayFlag, severity: enriched.severity },
        });
      }
    }
    await updateIntelligenceSource(source.id, { lastSuccessAt: new Date(), lastError: null });
    await finishIngestionRun(runId, { status: "completed", itemsFetched: items.length, itemsCreated, itemsUpdated });
    await appendAuditEvent({ actor, eventType: "ingestion.completed", entityType: "source", entityId: String(source.id), payload: { runId, itemsFetched: items.length, itemsCreated, itemsUpdated } });
    return { sourceId: source.id, status: "completed" as const, itemsFetched: items.length, itemsCreated, itemsUpdated };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    await updateIntelligenceSource(source.id, { lastError: message });
    await finishIngestionRun(runId, { status: "failed", errorMessage: message });
    await appendAuditEvent({ actor, eventType: "ingestion.failed", entityType: "source", entityId: String(source.id), payload: { runId, error: message } });
    throw error;
  }
}

export async function ingestAllSources(actor: IngestionActor) {
  const { listIntelligenceSources } = await import("../db");
  const sources = await listIntelligenceSources();
  const outcomes = [];
  for (const source of sources.filter(source => source.enabled)) {
    try {
      outcomes.push(await ingestSource(source.id, actor));
    } catch (error) {
      outcomes.push({ sourceId: source.id, status: "failed" as const, message: error instanceof Error ? error.message : String(error) });
    }
  }
  return outcomes;
}

export async function ingestScheduledSource(taskUid: string) {
  const source = await getIntelligenceSourceByTaskUid(taskUid);
  if (!source) return { ok: true, skipped: "orphan" };
  const outcome = await ingestSource(source.id, { kind: "schedule", id: taskUid });
  return { ok: true, outcome };
}

function clip(value: string, length: number) {
  return value.length > length ? `${value.slice(0, length - 1)}…` : value;
}

export async function generateThreatBrief(threatId: number, actor: IngestionActor) {
  const threat = await getThreat(threatId);
  if (!threat) throw new Error("Threat item not found");
  const response = await invokeLLM({
    model: BRIEF_MODEL,
    maxTokens: 220,
    messages: [
      { role: "system", content: "You are a cybersecurity analyst. Write a concise, source-grounded intelligence brief. Do not assert exploitation, attribution, impact, or remediation beyond the supplied record. State uncertainty plainly. Use 2 short paragraphs with no markdown heading." },
      { role: "user", content: `Threat record\nCVE: ${threat.cveId ?? "not supplied"}\nTitle: ${clip(threat.title, 600)}\nSeverity: ${threat.severity}\nCVSS: ${threat.cvssScore ?? "not supplied"}\nAffected stack: ${(threat.affectedStack ?? []).join(", ") || "not supplied"}\nGeo tags: ${(threat.extractedGeoTags ?? []).join(", ") || "not supplied"}\nZero-day indicator: ${threat.zeroDayFlag}\nKnown exploited indicator: ${threat.knownExploitedFlag}\nSource: ${threat.sourceUrl}\nDescription: ${clip(threat.description, 5000)}` },
    ],
  });
  const briefContent = response.choices[0]?.message?.content;
  const brief = typeof briefContent === "string" ? briefContent.trim() : "";
  if (!brief) throw new Error("The analyst-brief model returned no content");
  await updateThreatBrief(threat.id, brief, BRIEF_MODEL);
  await appendAuditEvent({ actor, eventType: "brief.generated", entityType: "threat", entityId: String(threat.id), payload: { model: BRIEF_MODEL } });
  return { brief, model: BRIEF_MODEL, generatedAt: new Date() };
}

export async function generateDailyDigest(actor: IngestionActor) {
  const { listThreats } = await import("../db");
  const threats = await listThreats(12);
  if (!threats.length) return { digest: "No ingested intelligence is available yet. Run a source synchronization to build the current briefing.", model: BRIEF_MODEL };
  const records = threats.map(threat => ({
    cve: threat.cveId ?? threat.ghsaId ?? `item-${threat.id}`,
    severity: threat.severity,
    title: clip(threat.title, 180),
    cvss: threat.cvssScore,
    zeroDay: threat.zeroDayFlag,
    knownExploited: threat.knownExploitedFlag,
  }));
  const response = await invokeLLM({
    model: BRIEF_MODEL,
    maxTokens: 320,
    messages: [
      { role: "system", content: "You are a cybersecurity analyst. Write a concise daily threat digest from the supplied source records only. Prioritize Critical severity, declared zero-day indicators, known-exploited indicators, and high CVSS. Do not claim facts not in the input. Use plain text in 3 short paragraphs." },
      { role: "user", content: JSON.stringify(records) },
    ],
  });
  const digestContent = response.choices[0]?.message?.content;
  const digest = typeof digestContent === "string" ? digestContent.trim() : "";
  if (!digest) throw new Error("The daily-digest model returned no content");
  await appendAuditEvent({ actor, eventType: "digest.generated", entityType: "report", payload: { model: BRIEF_MODEL, threatCount: threats.length } });
  return { digest, model: BRIEF_MODEL };
}
