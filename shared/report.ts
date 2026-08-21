export type ReportThreat = {
  identifier: string;
  severity: "Critical" | "High" | "Medium" | "Low";
  cvssScore?: string | number | null;
  title: string;
  sourceUrl: string;
};

export type ReportAuditEvent = { createdAt: Date | string; eventType: string; eventHash: string };

export function buildReportPayload(input: {
  generatedAt: Date;
  counts: { Critical: number; High: number; Medium: number; Low: number };
  dailyDigest?: string;
  threats: ReportThreat[];
  auditEvents: ReportAuditEvent[];
}) {
  return {
    generatedAt: input.generatedAt.toISOString(),
    triage: input.counts,
    dailyDigest: input.dailyDigest ?? "No daily brief has been generated. This report summarizes retained source records only.",
    topThreats: input.threats.slice(0, 8),
    auditExcerpt: input.auditEvents.slice(0, 6).map(event => ({ ...event, createdAt: new Date(event.createdAt).toISOString(), eventHash: event.eventHash.slice(0, 16) })),
  };
}
