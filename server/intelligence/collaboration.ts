import { ENV } from "../_core/env";

export type WebhookChannel = "slack_webhook" | "teams_webhook";

export type CollaborationAlert = {
  title: string;
  detail: string;
  sourceUrl: string;
  severity: "Critical" | "High" | "Medium" | "Low";
};

export function collaborationAvailability(env: Pick<typeof ENV, "slackWebhookUrl" | "teamsWebhookUrl"> = ENV) {
  return { slackWebhook: Boolean(env.slackWebhookUrl), teamsWebhook: Boolean(env.teamsWebhookUrl) };
}

export function buildWebhookPayload(channel: WebhookChannel, alert: CollaborationAlert) {
  if (channel === "slack_webhook") {
    return { text: `*${alert.title}*\n${alert.detail}\nSeverity: ${alert.severity}\nSource: ${alert.sourceUrl}` };
  }
  return {
    "@type": "MessageCard",
    "@context": "https://schema.org/extensions",
    summary: alert.title,
    themeColor: alert.severity === "Critical" ? "DC2626" : "F59E0B",
    title: alert.title,
    text: `${alert.detail}<br/><br/><b>Severity:</b> ${alert.severity}<br/><a href="${alert.sourceUrl}">Open source record</a>`,
  };
}

export async function deliverWebhookAlert(channel: WebhookChannel, alert: CollaborationAlert) {
  const url = channel === "slack_webhook" ? ENV.slackWebhookUrl : ENV.teamsWebhookUrl;
  if (!url) return { attempted: false, delivered: false, reason: "not-configured" as const };
  try {
    const response = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(buildWebhookPayload(channel, alert)), signal: AbortSignal.timeout(8_000) });
    return response.ok ? { attempted: true, delivered: true, status: response.status } : { attempted: true, delivered: false, status: response.status };
  } catch {
    return { attempted: true, delivered: false, reason: "request-failed" as const };
  }
}
