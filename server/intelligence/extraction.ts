import { createHash } from "node:crypto";
import type { EnrichedThreat, GeoCandidate, NormalizedThreat, SeverityTier } from "./types";

const CVE_PATTERN = /\bCVE-\d{4}-\d{4,8}\b/gi;
const ZERO_DAY_PATTERN = /\b(zero[ -]?day|0[ -]?day|actively exploited|exploited in the wild)\b/i;
const KNOWN_EXPLOITED_PATTERN = /\b(known exploited|exploited in the wild|active exploitation|actively exploited)\b/i;

const STACK_TERMS = [
  "Apache", "Nginx", "Microsoft Exchange", "Microsoft Windows", "Active Directory", "Linux", "Kubernetes",
  "Docker", "GitLab", "GitHub", "Jenkins", "WordPress", "Drupal", "VMware", "Cisco", "Fortinet",
  "Palo Alto Networks", "Ivanti", "Atlassian", "Confluence", "Jira", "Oracle", "MySQL", "PostgreSQL",
  "MongoDB", "Redis", "OpenSSH", "OpenSSL", "Node.js", "npm", "Python", "Java", "Spring", "Ruby",
];

const GEO_CATALOG: Array<{ label: string; countryCode: string; latitude: number; longitude: number; patterns: RegExp[] }> = [
  { label: "United States", countryCode: "US", latitude: 39.8283, longitude: -98.5795, patterns: [/\bUnited States\b/i, /\bU\.S\.\b/] },
  { label: "United Kingdom", countryCode: "GB", latitude: 55.3781, longitude: -3.436, patterns: [/\bUnited Kingdom\b/i, /\bU\.K\.\b/] },
  { label: "Russia", countryCode: "RU", latitude: 61.524, longitude: 105.3188, patterns: [/\bRussia\b/i, /\bRussian\b/i] },
  { label: "Ukraine", countryCode: "UA", latitude: 48.3794, longitude: 31.1656, patterns: [/\bUkraine\b/i, /\bUkrainian\b/i] },
  { label: "China", countryCode: "CN", latitude: 35.8617, longitude: 104.1954, patterns: [/\bChina\b/i, /\bChinese\b/i] },
  { label: "North Korea", countryCode: "KP", latitude: 40.3399, longitude: 127.5101, patterns: [/\bNorth Korea\b/i, /\bNorth Korean\b/i] },
  { label: "South Korea", countryCode: "KR", latitude: 35.9078, longitude: 127.7669, patterns: [/\bSouth Korea\b/i, /\bSouth Korean\b/i] },
  { label: "Iran", countryCode: "IR", latitude: 32.4279, longitude: 53.688, patterns: [/\bIran\b/i, /\bIranian\b/i] },
  { label: "Israel", countryCode: "IL", latitude: 31.0461, longitude: 34.8516, patterns: [/\bIsrael\b/i, /\bIsraeli\b/i] },
  { label: "Germany", countryCode: "DE", latitude: 51.1657, longitude: 10.4515, patterns: [/\bGermany\b/i, /\bGerman\b/i] },
  { label: "France", countryCode: "FR", latitude: 46.2276, longitude: 2.2137, patterns: [/\bFrance\b/i, /\bFrench\b/i] },
  { label: "Japan", countryCode: "JP", latitude: 36.2048, longitude: 138.2529, patterns: [/\bJapan\b/i, /\bJapanese\b/i] },
  { label: "India", countryCode: "IN", latitude: 20.5937, longitude: 78.9629, patterns: [/\bIndia\b/i, /\bIndian\b/i] },
  { label: "Australia", countryCode: "AU", latitude: -25.2744, longitude: 133.7751, patterns: [/\bAustralia\b/i, /\bAustralian\b/i] },
  { label: "Canada", countryCode: "CA", latitude: 56.1304, longitude: -106.3468, patterns: [/\bCanada\b/i, /\bCanadian\b/i] },
  { label: "Brazil", countryCode: "BR", latitude: -14.235, longitude: -51.9253, patterns: [/\bBrazil\b/i, /\bBrazilian\b/i] },
];

export function severityFromScore(score?: number): SeverityTier {
  if (score === undefined || Number.isNaN(score)) return "Low";
  if (score >= 9) return "Critical";
  if (score >= 7) return "High";
  if (score >= 4) return "Medium";
  return "Low";
}

export function extractCveId(text: string): string | undefined {
  return text.match(CVE_PATTERN)?.[0]?.toUpperCase();
}

export function extractStackHints(text: string): string[] {
  const lowered = text.toLowerCase();
  return STACK_TERMS.filter(term => lowered.includes(term.toLowerCase()));
}

export function extractGeoCandidates(text: string): GeoCandidate[] {
  return GEO_CATALOG.flatMap(entry => {
    const matched = entry.patterns.some(pattern => pattern.test(text));
    return matched
      ? [{
          label: entry.label,
          countryCode: entry.countryCode,
          latitude: entry.latitude,
          longitude: entry.longitude,
          confidence: 0.78,
          extractionMethod: "rule" as const,
        }]
      : [];
  });
}

export function stripHtml(value: string): string {
  return value
    .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, "$1")
    .replace(/<[^>]*>/g, " ")
    .replace(/&nbsp;/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&#8217;/g, "’")
    .replace(/&#8216;/g, "‘")
    .replace(/&#8220;/g, "“")
    .replace(/&#8221;/g, "”")
    .replace(/\s+/g, " ")
    .trim();
}

export function contentHash(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

export function enrichThreat(threat: NormalizedThreat): EnrichedThreat {
  const combined = `${threat.title}\n${threat.description}\n${threat.rawText}`;
  const affectedStack = Array.from(new Set([...threat.affectedStack, ...extractStackHints(combined)])).slice(0, 24);
  const geoObservations = extractGeoCandidates(combined);
  return {
    ...threat,
    cveId: threat.cveId ?? extractCveId(combined),
    affectedStack,
    severity: threat.severity ?? severityFromScore(threat.cvssScore),
    extractedGeoTags: geoObservations.map(observation => observation.label),
    geoObservations,
    zeroDayFlag: ZERO_DAY_PATTERN.test(combined),
    knownExploitedFlag: KNOWN_EXPLOITED_PATTERN.test(combined),
    rawContentHash: contentHash(combined),
  };
}
