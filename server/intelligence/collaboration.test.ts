import { describe, expect, it } from "vitest";
import { buildWebhookPayload, collaborationAvailability } from "./collaboration";

const alert = { title: "Critical signal", detail: "CVE-2026-0001 · NVD · Critical", sourceUrl: "https://example.test/CVE-2026-0001", severity: "Critical" as const };

describe("collaboration delivery", () => {
  it("builds source-linked Slack and Teams-compatible payloads", () => {
    expect(buildWebhookPayload("slack_webhook", alert)).toMatchObject({ text: expect.stringContaining(alert.sourceUrl) });
    expect(buildWebhookPayload("teams_webhook", alert)).toMatchObject({ title: alert.title, themeColor: "DC2626" });
  });

  it("reports availability without exposing any configured URL", () => {
    expect(collaborationAvailability({ slackWebhookUrl: "https://hooks.slack.test/secret", teamsWebhookUrl: "" })).toEqual({ slackWebhook: true, teamsWebhook: false });
  });
});
