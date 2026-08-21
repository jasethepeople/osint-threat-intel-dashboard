import { EmptyTelemetry, LiveSignal, PanelTitle, SeverityBadge, TerminalHeader, dateTime } from "@/components/threat-ui";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { trpc } from "@/lib/trpc";
import WatchlistRouting from "@/components/WatchlistRouting";
import RetentionControl from "@/components/RetentionControl";
import { ExternalLink, Play, Save, Settings2 } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";

function SourceControl({ source }: { source: { id: number; name: string; kind: "nvd" | "github" | "rss"; enabled: boolean; endpoint: string; pollIntervalMinutes: number; lastSuccessAt: Date | null; lastError: string | null } }) {
  const utils = trpc.useUtils();
  const [interval, setInterval] = useState(String(source.pollIntervalMinutes));
  const [enabled, setEnabled] = useState(source.enabled);
  const configure = trpc.intelligence.configureSource.useMutation({ onSuccess: () => { toast.success(`${source.name} schedule saved.`); void utils.intelligence.sources.invalidate(); }, onError: error => toast.error(error.message) });
  const run = trpc.intelligence.runSource.useMutation({ onSuccess: outcome => { toast.success(`${source.name}: ${outcome.itemsFetched} source items checked.`); void utils.intelligence.invalidate(); }, onError: error => toast.error(error.message) });
  const save = () => {
    const minutes = Number(interval);
    if (!Number.isInteger(minutes) || minutes < 15 || minutes > 60) return toast.error("Polling interval must be a whole number from 15 to 60 minutes.");
    configure.mutate({ sourceId: source.id, enabled, pollIntervalMinutes: minutes });
  };
  return <article className="border border-border bg-black/15 p-4"><div className="flex flex-wrap items-start justify-between gap-3"><div><p className="font-mono text-xs font-semibold text-foreground">{source.name}</p><p className="mt-1 font-mono text-[10px] uppercase tracking-[0.15em] text-primary">{source.kind} adapter</p></div><label className="flex items-center gap-2 font-mono text-[10px] uppercase tracking-wider text-muted-foreground"><input type="checkbox" checked={enabled} onChange={event => setEnabled(event.target.checked)} className="accent-[#F59E0B]" />Enabled</label></div>
    <p className="mt-3 truncate font-mono text-[10px] text-muted-foreground">{source.endpoint}</p><div className="mt-4 grid grid-cols-[1fr_auto_auto] gap-2"><Input value={interval} onChange={event => setInterval(event.target.value)} inputMode="numeric" aria-label={`${source.name} polling interval`} className="h-8 rounded-none border-primary/25 bg-black/30 font-mono text-xs" /><Button onClick={save} disabled={configure.isPending} variant="outline" size="sm" className="h-8 rounded-none border-primary/40 px-2 font-mono text-[10px] text-primary"><Save className="mr-1 h-3 w-3" />Save</Button><Button onClick={() => run.mutate({ sourceId: source.id })} disabled={run.isPending || !enabled} size="sm" className="h-8 rounded-none bg-primary px-2 font-mono text-[10px] text-primary-foreground"><Play className="mr-1 h-3 w-3" />Run</Button></div><p className="mt-2 font-mono text-[9px] text-muted-foreground">{enabled ? `EVERY ${interval || "?"} MINUTES` : "PAUSED"} · LAST SUCCESS {dateTime(source.lastSuccessAt)}</p>{source.lastError ? <p className="mt-2 font-mono text-[10px] text-destructive">LAST ERROR: {source.lastError}</p> : null}</article>;
}

export default function CveFeed() {
  const sources = trpc.intelligence.sources.useQuery(undefined, { refetchInterval: 30_000 });
  const threats = trpc.intelligence.threats.useQuery({ limit: 120 }, { refetchInterval: 20_000 });
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState("all");
  const filteredThreats = (threats.data ?? []).filter(threat => {
    const haystack = `${threat.cveId ?? ""} ${threat.ghsaId ?? ""} ${threat.title} ${(threat.affectedStack ?? []).join(" ")}`.toLowerCase();
    return haystack.includes(query.trim().toLowerCase()) && (severity === "all" || threat.severity === severity);
  });
  return <>
    <TerminalHeader eyebrow="CVE Feed / Source Operations" title="Live CVE & advisory feed" description="Each adapter retains its original source URL and publishes normalized CVE, package, scoring, and source timestamps. Polling is configurable from 15 to 60 minutes after the site is published." actions={<LiveSignal label="source-linked" />} />
    <section className="mb-6 terminal-panel p-4 md:p-5"><PanelTitle label="Polling control" title="Intelligence source adapters" right={<Settings2 className="h-4 w-4 text-primary" />} />{sources.isLoading ? <div className="grid gap-3 lg:grid-cols-2"><div className="h-44 animate-pulse bg-muted/30" /><div className="h-44 animate-pulse bg-muted/30" /></div> : sources.error ? <EmptyTelemetry title="Source controls unavailable" body={sources.error.message} /> : <div className="grid gap-3 lg:grid-cols-2">{sources.data?.map(source => <SourceControl key={source.id} source={source} />)}</div>}</section>
    <WatchlistRouting />
    <RetentionControl />
    <section className="terminal-panel p-4 md:p-5"><PanelTitle label="Normalized stream" title="Latest retained records" right={<span className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">{threats.data?.length ?? 0} records</span>} />
      <div className="mb-4 grid gap-2 sm:grid-cols-[minmax(0,1fr)_180px]"><Input value={query} onChange={event => setQuery(event.target.value)} placeholder="Filter CVE, GHSA, title, or stack" className="h-9 rounded-none border-primary/25 bg-black/30 font-mono text-xs" /><select value={severity} onChange={event => setSeverity(event.target.value)} className="h-9 border border-primary/25 bg-black/30 px-3 font-mono text-xs text-foreground outline-none focus:border-primary"><option value="all">All severities</option><option value="Critical">Critical</option><option value="High">High</option><option value="Medium">Medium</option><option value="Low">Low</option></select></div>
      {threats.isLoading ? <div className="h-64 animate-pulse bg-muted/30" /> : threats.error ? <EmptyTelemetry title="Threat feed unavailable" body={threats.error.message} /> : filteredThreats.length ? <div className="overflow-x-auto"><table className="w-full min-w-[780px] text-left"><thead><tr className="border-b border-primary/20 font-mono text-[9px] uppercase tracking-[0.16em] text-muted-foreground"><th className="pb-3 pr-4">Identifier</th><th className="pb-3 pr-4">Source record</th><th className="pb-3 pr-4">Stack</th><th className="pb-3 pr-4">Severity</th><th className="pb-3 pr-4">Ingested</th><th className="pb-3">Provenance</th></tr></thead><tbody>{filteredThreats.map(threat => <tr key={threat.id} className="border-b border-border/70 font-mono text-[11px] hover:bg-primary/[0.035]"><td className="py-3 pr-4 font-semibold text-primary">{threat.cveId ?? threat.ghsaId ?? "NEWS"}</td><td className="max-w-sm py-3 pr-4 text-foreground"><p className="line-clamp-2">{threat.title}</p><p className="mt-1 text-[9px] text-muted-foreground">CVSS {threat.cvssScore ?? "—"}</p></td><td className="py-3 pr-4 text-muted-foreground">{(threat.affectedStack ?? []).slice(0, 2).join(", ") || "—"}</td><td className="py-3 pr-4"><SeverityBadge severity={threat.severity} /></td><td className="py-3 pr-4 text-muted-foreground">{dateTime(threat.ingestionTimestamp)}</td><td className="py-3"><a href={threat.sourceUrl} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-primary hover:underline"><ExternalLink className="h-3 w-3" />Open</a></td></tr>)}</tbody></table></div> : <EmptyTelemetry title={threats.data?.length ? "No records match this filter" : "No live source records"} body={threats.data?.length ? "Change the matching terms or severity tier to expand the retained-record view." : "No mock CVEs are displayed. Start a source run above to retrieve public data and populate this normalized feed."} />}
    </section>
  </>;
}
