export type RetentionTimelineEvent = { id: number; eventType: string; payload: Record<string, unknown>; createdAt: Date; actorKind: string; eventHash: string; previousHash: string | null };
export type RetentionTimelineFilter = "all" | "purges" | "configuration";

export function retentionPayloadValue(payload: Record<string, unknown>, key: string) {
  const value = payload[key];
  return typeof value === "string" || typeof value === "number" || typeof value === "boolean" ? String(value) : "";
}

export function filterRetentionTimeline(events: RetentionTimelineEvent[], filter: RetentionTimelineFilter) {
  return events.filter(event => filter === "all" ? true : filter === "purges" ? event.eventType === "retention.completed" : event.eventType !== "retention.completed");
}
