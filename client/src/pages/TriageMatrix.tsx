import { EmptyTelemetry, LiveSignal, PanelTitle, SeverityBadge, TerminalHeader, dateTime, severityOrder } from "@/components/threat-ui";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { trpc } from "@/lib/trpc";
import { BookmarkCheck, BookmarkPlus, BrainCircuit, RefreshCw, Trash2 } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";
import { matchesTriageScope } from "@shared/triage";

export default function TriageMatrix() {
  const utils = trpc.useUtils();
  const threats = trpc.intelligence.threats.useQuery({ limit: 120 }, { refetchInterval: 20_000 });
  const views = trpc.intelligence.triageViews.useQuery();
  const [activeViewId, setActiveViewId] = useState<number | null>(null);
  const [viewName, setViewName] = useState("");
  const [stackTerms, setStackTerms] = useState("");
  const [selectedSeverities, setSelectedSeverities] = useState<string[]>([...severityOrder]);
  const brief = trpc.intelligence.generateBrief.useMutation({
    onSuccess: () => { toast.success("Analyst brief generated from the source record."); void utils.intelligence.threats.invalidate(); },
    onError: error => toast.error(error.message),
  });
  const createView = trpc.intelligence.createTriageView.useMutation({
    onSuccess: async () => { setViewName(""); setStackTerms(""); await utils.intelligence.triageViews.invalidate(); toast.success("Business-unit triage view saved."); },
    onError: error => toast.error(error.message),
  });
  const deleteView = trpc.intelligence.deleteTriageView.useMutation({
    onSuccess: async () => { setActiveViewId(null); await utils.intelligence.triageViews.invalidate(); toast.success("Saved triage view removed."); },
    onError: error => toast.error(error.message),
  });
  const activeView = (views.data ?? []).find(view => view.id === activeViewId && view.enabled) ?? null;
  const scopedThreats = (threats.data ?? []).filter(threat => {
    if (!activeView) return true;
    return matchesTriageScope(threat, activeView);
  });
  const grouped = severityOrder.reduce((collection, severity) => ({ ...collection, [severity]: scopedThreats.filter(threat => threat.severity === severity) }), {} as Record<(typeof severityOrder)[number], typeof scopedThreats>);
  const toggleSeverity = (severity: string) => setSelectedSeverities(current => current.includes(severity) ? current.filter(item => item !== severity) : [...current, severity]);
  const saveView = () => {
    const terms = stackTerms.split(",").map(term => term.trim()).filter(Boolean);
    if (viewName.trim().length < 2 || !terms.length || !selectedSeverities.length) return toast.error("Provide a view name, one or more stack terms, and at least one severity.");
    createView.mutate({ name: viewName.trim(), stackTerms: terms, severities: selectedSeverities as (typeof severityOrder)[number][], enabled: true });
  };

  return <>
    <TerminalHeader eyebrow="Triage Matrix / Priority Queue" title="Priority triage matrix" description="Records auto-refresh every 20 seconds. Select a business-unit scope to focus on source-derived affected-stack matches without changing the global retention set." actions={<LiveSignal label="20s refresh" />} />
    <section className="mb-5 terminal-panel p-4 md:p-5"><PanelTitle label="Business-unit scope" title="Saved triage views" right={<BookmarkCheck className="h-4 w-4 text-primary" />} />
      <div className="flex flex-wrap gap-2"><Button onClick={() => setActiveViewId(null)} variant={activeViewId === null ? "default" : "outline"} className="h-8 rounded-none px-3 font-mono text-[10px] uppercase tracking-wider">All intelligence</Button>{(views.data ?? []).filter(view => view.enabled).map(view => <div key={view.id} className="flex"><Button onClick={() => setActiveViewId(view.id)} variant={activeViewId === view.id ? "default" : "outline"} className="h-8 rounded-none rounded-r-none border-primary/35 px-3 font-mono text-[10px] uppercase tracking-wider">{view.name}</Button><Button onClick={() => deleteView.mutate({ id: view.id })} variant="outline" className="h-8 rounded-none rounded-l-none border-l-0 border-primary/35 px-2 text-destructive hover:bg-destructive/10"><Trash2 className="h-3.5 w-3.5" /></Button></div>)}</div>
      <div className="mt-4 grid gap-2 lg:grid-cols-[180px_minmax(0,1fr)_auto]"><Input value={viewName} onChange={event => setViewName(event.target.value)} placeholder="Business unit name" className="h-9 rounded-none border-primary/25 bg-black/30 font-mono text-xs" /><Input value={stackTerms} onChange={event => setStackTerms(event.target.value)} placeholder="Affected stack terms, comma separated" className="h-9 rounded-none border-primary/25 bg-black/30 font-mono text-xs" /><Button onClick={saveView} disabled={createView.isPending} className="h-9 rounded-none bg-primary px-3 font-mono text-[10px] uppercase text-primary-foreground"><BookmarkPlus className="mr-1.5 h-3.5 w-3.5" />Save scope</Button></div>
      <div className="mt-3 flex flex-wrap gap-3">{severityOrder.map(severity => <label key={severity} className="flex items-center gap-1.5 font-mono text-[10px] uppercase text-muted-foreground"><input type="checkbox" checked={selectedSeverities.includes(severity)} onChange={() => toggleSeverity(severity)} className="accent-[#F59E0B]" />{severity}</label>)}</div>
      <p className="mt-3 font-mono text-[10px] text-muted-foreground">{activeView ? `ACTIVE: ${activeView.name} · ${activeView.stackTerms.join(" · ")} · ${activeView.severities.join(", ")}` : "Global view active. Save named units to focus the matrix by stack and severity."}</p>
    </section>
    <div className="grid gap-4 xl:grid-cols-4">
      {severityOrder.map(severity => <section key={severity} className="terminal-panel min-h-[530px] p-3"><PanelTitle label="Severity tier" title={severity} right={<span className="font-mono text-xs text-muted-foreground">{grouped[severity].length}</span>} />
        <div className="space-y-3">
          {grouped[severity].length ? grouped[severity].map(threat => <article key={threat.id} className="border border-border bg-black/15 p-3 transition-colors hover:border-primary/35">
            <div className="flex items-start justify-between gap-2"><p className="font-mono text-[11px] font-semibold text-foreground">{threat.cveId ?? threat.ghsaId ?? "NEWS SIGNAL"}</p><SeverityBadge severity={threat.severity} /></div>
            <p className="mt-2 line-clamp-3 font-mono text-[11px] leading-5 text-foreground/90">{threat.title}</p>
            <div className="mt-3 flex flex-wrap gap-1">{(threat.affectedStack ?? []).slice(0, 3).map((stack: string) => <span key={stack} className="border border-primary/20 bg-primary/5 px-1.5 py-0.5 font-mono text-[9px] text-primary">{stack}</span>)}</div>
            {threat.zeroDayFlag || threat.knownExploitedFlag ? <p className="mt-3 font-mono text-[10px] uppercase tracking-wider text-destructive">{threat.zeroDayFlag ? "zero-day language" : "exploitation language"}</p> : null}
            {threat.analystBrief ? <div className="mt-3 border-l-2 border-primary/60 bg-primary/5 p-2"><p className="font-mono text-[9px] uppercase tracking-[0.13em] text-primary">Inline analyst brief</p><p className="mt-1 whitespace-pre-line font-mono text-[10px] leading-4 text-muted-foreground">{threat.analystBrief}</p></div> : <Button variant="outline" size="sm" onClick={() => brief.mutate({ threatId: threat.id })} disabled={brief.isPending} className="mt-3 h-7 rounded-none border-primary/40 px-2 font-mono text-[9px] uppercase tracking-wider text-primary hover:bg-primary/10"><BrainCircuit className={brief.isPending ? "mr-1.5 h-3 w-3 animate-pulse" : "mr-1.5 h-3 w-3"} />Brief</Button>}
            <p className="mt-3 font-mono text-[9px] text-muted-foreground">INGESTED {dateTime(threat.ingestionTimestamp)}</p>
          </article>) : <EmptyTelemetry title={`No ${severity} records`} body={activeView ? "No retained records match this business-unit scope." : "This tier contains no live records in the current retention window."} />}
        </div>
      </section>)}
    </div>
    <div className="mt-5 flex items-center gap-2 border border-primary/20 bg-primary/5 px-3 py-2"><RefreshCw className="h-3.5 w-3.5 text-primary" /><p className="font-mono text-[10px] uppercase tracking-[0.15em] text-muted-foreground">Live query status: {threats.isFetching ? "refreshing" : "synchronized"} · {scopedThreats.length} scoped records</p></div>
  </>;
}
