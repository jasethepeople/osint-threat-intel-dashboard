export function retentionCutoff(retentionDays: number, now = new Date()) {
  return new Date(now.getTime() - retentionDays * 24 * 60 * 60 * 1000);
}

export function isEligibleForRetention(ingestionTimestamp: Date, retentionDays: number, now = new Date()) {
  return ingestionTimestamp < retentionCutoff(retentionDays, now);
}
