export type TriageScope = { stackTerms: string[]; severities: string[] };
export type TriageThreat = { severity: string; affectedStack: string[] | null };

export function matchesTriageScope(threat: TriageThreat, scope: TriageScope) {
  if (!scope.severities.includes(threat.severity)) return false;
  const terms = scope.stackTerms.map(term => term.trim().toLowerCase()).filter(Boolean);
  if (!terms.length) return false;
  return terms.some(term => (threat.affectedStack ?? []).some(stack => stack.toLowerCase().includes(term)));
}
