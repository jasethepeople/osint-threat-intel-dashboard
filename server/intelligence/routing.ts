import { listEnabledAlertRoutes, listEnabledWatchlists } from "../db";
import type { EnrichedThreat } from "./types";

const severityWeight = { Low: 1, Medium: 2, High: 3, Critical: 4 } as const;
type AlertRoute = { watchlistId: number | null; minSeverity: keyof typeof severityWeight; includeZeroDays: boolean; includeKnownExploited: boolean };
type Watchlist = { id: number; stackTerms: string[] };

export function containsWatchTerm(threat: EnrichedThreat, term: string) {
  const needle = term.trim().toLowerCase();
  if (!needle) return false;
  return threat.affectedStack.some(stack => stack.toLowerCase().includes(needle));
}

export function matchesAlertRoute(threat: EnrichedThreat, route: AlertRoute, watchlists: Watchlist[]) {
  const severityMatch = severityWeight[threat.severity] >= severityWeight[route.minSeverity];
  const flagMatch = (route.includeZeroDays && threat.zeroDayFlag) || (route.includeKnownExploited && threat.knownExploitedFlag);
  if (!severityMatch && !flagMatch) return false;
  if (!route.watchlistId) return true;
  const watchlist = watchlists.find(candidate => candidate.id === route.watchlistId);
  return Boolean(watchlist && watchlist.stackTerms.some(term => containsWatchTerm(threat, term)));
}

/** Finds enabled, source-grounded owner-notification routes for a newly created threat. */
export async function matchAlertRoutes(threat: EnrichedThreat) {
  const [routes, watchlists] = await Promise.all([listEnabledAlertRoutes(), listEnabledWatchlists()]);
  return routes.filter(route => matchesAlertRoute(threat, route, watchlists));
}
