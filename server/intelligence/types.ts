import type { sourceKinds, severityTiers } from "../../drizzle/schema";

export type SourceKind = (typeof sourceKinds)[number];
export type SeverityTier = (typeof severityTiers)[number];

export type GeoCandidate = {
  label: string;
  countryCode?: string;
  latitude?: number;
  longitude?: number;
  confidence: number;
  extractionMethod: "rule" | "source";
};

export type NormalizedThreat = {
  sourceExternalId: string;
  cveId?: string;
  ghsaId?: string;
  title: string;
  description: string;
  sourceUrl: string;
  sourcePublishedAt?: Date;
  sourceUpdatedAt?: Date;
  cvssScore?: number;
  severity?: SeverityTier;
  affectedStack: string[];
  rawText: string;
};

export type EnrichedThreat = NormalizedThreat & {
  cveId?: string;
  affectedStack: string[];
  severity: SeverityTier;
  extractedGeoTags: string[];
  geoObservations: GeoCandidate[];
  zeroDayFlag: boolean;
  knownExploitedFlag: boolean;
  rawContentHash: string;
};

export type IngestionActor = {
  kind: "system" | "user" | "schedule";
  id?: string;
};
