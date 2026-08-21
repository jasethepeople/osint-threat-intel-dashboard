import type { IntelligenceSource } from "../../drizzle/schema";
import { extractCveId, severityFromScore, stripHtml } from "./extraction";
import type { NormalizedThreat, SeverityTier } from "./types";

const NVD_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const GITHUB_ENDPOINT = "https://api.github.com/advisories";
const SECURITY_WEEK_RSS_ENDPOINT = "https://www.securityweek.com/feed/";
const HACKER_NEWS_RSS_ENDPOINT = "https://feeds.feedburner.com/TheHackersNews";

export const DEFAULT_SOURCES = [
  { sourceKey: "nvd-cve", name: "NVD CVE API", kind: "nvd" as const, endpoint: NVD_ENDPOINT },
  { sourceKey: "github-global-advisories", name: "GitHub Global Security Advisories", kind: "github" as const, endpoint: GITHUB_ENDPOINT },
  { sourceKey: "securityweek-rss", name: "SecurityWeek RSS", kind: "rss" as const, endpoint: SECURITY_WEEK_RSS_ENDPOINT },
  { sourceKey: "the-hacker-news-rss", name: "The Hacker News RSS", kind: "rss" as const, endpoint: HACKER_NEWS_RSS_ENDPOINT },
];

function parseDate(value?: string | null): Date | undefined {
  if (!value) return undefined;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? undefined : date;
}

function mostRecentWindow(source: IntelligenceSource, hours = 24): { start: Date; end: Date } {
  const end = new Date();
  const start = source.lastSuccessAt ?? new Date(end.getTime() - hours * 60 * 60 * 1000);
  // Sources may limit date windows. A one-minute overlap avoids missing boundary updates.
  return { start: new Date(start.getTime() - 60_000), end };
}

function parseNvdStack(vulnerability: any): string[] {
  const values = new Set<string>();
  const walk = (node: any) => {
    for (const match of node?.cpeMatch ?? []) {
      const cpe = String(match.criteria ?? "");
      const segments = cpe.split(":");
      if (segments.length > 4 && segments[3] && segments[4]) {
        values.add(`${segments[3]}/${segments[4]}`.replace(/\\/g, ""));
      }
    }
    for (const child of node?.nodes ?? []) walk(child);
  };
  for (const node of vulnerability.configurations?.nodes ?? []) walk(node);
  return Array.from(values).slice(0, 24);
}

function normalizeNvd(vulnerability: any): NormalizedThreat | null {
  const cve = vulnerability?.cve;
  const id = cve?.id as string | undefined;
  const description = cve?.descriptions?.find((entry: any) => entry.lang === "en")?.value ?? cve?.descriptions?.[0]?.value;
  if (!id || !description) return null;
  const metric = cve.metrics?.cvssMetricV40?.[0]?.cvssData ?? cve.metrics?.cvssMetricV31?.[0]?.cvssData ?? cve.metrics?.cvssMetricV30?.[0]?.cvssData;
  const score = typeof metric?.baseScore === "number" ? metric.baseScore : undefined;
  const references = cve.references?.map((reference: any) => reference.url).filter(Boolean) ?? [];
  return {
    sourceExternalId: id,
    cveId: id,
    title: id,
    description: stripHtml(description),
    sourceUrl: `https://nvd.nist.gov/vuln/detail/${id}`,
    sourcePublishedAt: parseDate(cve.published),
    sourceUpdatedAt: parseDate(cve.lastModified),
    cvssScore: score,
    severity: severityFromScore(score),
    affectedStack: parseNvdStack(vulnerability),
    rawText: `${description}\n${references.join("\n")}`,
  };
}

function githubSeverity(value?: string): SeverityTier | undefined {
  const normalized = value?.toLowerCase();
  if (!normalized) return undefined;
  return normalized.charAt(0).toUpperCase() + normalized.slice(1) as SeverityTier;
}

function normalizeGitHub(advisory: any): NormalizedThreat | null {
  const identifier = advisory?.ghsa_id ?? advisory?.cve_id;
  const title = advisory?.summary ?? advisory?.cve_id;
  if (!identifier || !title) return null;
  const stacks = (advisory.vulnerabilities ?? [])
    .map((vulnerability: any) => `${vulnerability.package?.ecosystem ?? "package"}/${vulnerability.package?.name ?? "unknown"}`)
    .filter(Boolean);
  const cveId = advisory.cve_id ?? advisory.identifiers?.find((entry: any) => entry.type === "CVE")?.value ?? extractCveId(advisory.description ?? "");
  const score = typeof advisory.cvss?.score === "number" ? advisory.cvss.score : advisory.cvss_severities?.cvss_v4?.score;
  return {
    sourceExternalId: identifier,
    cveId,
    ghsaId: advisory.ghsa_id,
    title: stripHtml(title),
    description: stripHtml(advisory.description ?? title),
    sourceUrl: advisory.html_url ?? advisory.url,
    sourcePublishedAt: parseDate(advisory.published_at),
    sourceUpdatedAt: parseDate(advisory.updated_at),
    cvssScore: score,
    severity: githubSeverity(advisory.severity) ?? severityFromScore(score),
    affectedStack: stacks,
    rawText: `${advisory.description ?? ""}\n${(advisory.references ?? []).join("\n")}`,
  };
}

function xmlTag(block: string, tag: string): string | undefined {
  const match = block.match(new RegExp(`<${tag}(?:\\s[^>]*)?>([\\s\\S]*?)<\\/${tag}>`, "i"));
  return match?.[1] ? stripHtml(match[1]) : undefined;
}

function normalizeRss(xml: string): NormalizedThreat[] {
  const blocks = Array.from(xml.matchAll(/<item(?:\s[^>]*)?>([\s\S]*?)<\/item>/gi)).map(match => match[1]);
  return blocks.slice(0, 30).flatMap(block => {
    const title = xmlTag(block, "title");
    const description = xmlTag(block, "description") ?? title;
    const link = xmlTag(block, "link");
    const guid = xmlTag(block, "guid") ?? link;
    if (!title || !description || !link || !guid) return [];
    return [{
      sourceExternalId: guid.slice(0, 255),
      cveId: extractCveId(`${title}\n${description}`),
      title,
      description,
      sourceUrl: link,
      sourcePublishedAt: parseDate(xmlTag(block, "pubDate")),
      affectedStack: [],
      rawText: `${title}\n${description}`,
    } satisfies NormalizedThreat];
  });
}

async function parseResponse(response: Response): Promise<any> {
  if (!response.ok) throw new Error(`Source request failed (${response.status})`);
  return response.json();
}

export async function fetchSourceThreats(source: IntelligenceSource): Promise<NormalizedThreat[]> {
  if (source.kind === "nvd") {
    const { start, end } = mostRecentWindow(source);
    const params = new URLSearchParams({
      lastModStartDate: start.toISOString(),
      lastModEndDate: end.toISOString(),
      resultsPerPage: "100",
    });
    const data = await parseResponse(await fetch(`${source.endpoint}?${params.toString()}`, { headers: { "User-Agent": "SentinelAtlas/1.0" } }));
    return (data.vulnerabilities ?? [])
      .map(normalizeNvd)
      .filter((threat: NormalizedThreat | null): threat is NormalizedThreat => threat !== null)
      .slice(0, 100);
  }
  if (source.kind === "github") {
    const { start, end } = mostRecentWindow(source);
    const params = new URLSearchParams({ updated: `>=${start.toISOString()}..${end.toISOString()}`, per_page: "100", sort: "updated", direction: "desc" });
    const data = await parseResponse(await fetch(`${source.endpoint}?${params.toString()}`, {
      headers: { "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2026-03-10", "User-Agent": "SentinelAtlas/1.0" },
    }));
    return Array.isArray(data)
      ? data
          .map(normalizeGitHub)
          .filter((threat: NormalizedThreat | null): threat is NormalizedThreat => threat !== null)
          .slice(0, 100)
      : [];
  }
  const response = await fetch(source.endpoint, { headers: { "User-Agent": "SentinelAtlas/1.0" } });
  if (!response.ok) throw new Error(`Source request failed (${response.status})`);
  return normalizeRss(await response.text());
}
