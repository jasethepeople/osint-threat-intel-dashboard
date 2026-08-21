import { EmptyTelemetry, LiveSignal, PanelTitle, SeverityBadge, TerminalHeader, dateTime, severityOrder } from "@/components/threat-ui";
import { Button } from "@/components/ui/button";
import { trpc } from "@/lib/trpc";
import { BrainCircuit, RefreshCw } from "lucide-react";
import { toast } from "sonner";

export default function TriageMatrix() {
  const utils = trpc.useUtils();
  const threats = trpc.intelligence.threats.useQuery({ limit: 120 }, { refetchInterval: 20_000 });
  const brief = trpc.intelligence.generateBrief.useMutation({
    onSuccess: () => { toast.success("Analyst brief generated from the source record."); void utils.intelligence.threats.invalidate(); },
    onError: error => toast.error(error.message),
  });
  const grouped = severityOrder.reduce((collection, severity) => ({ ...collection, [severity]: (threats.data ?? []).filter(threat => threat.severity === severity) }), {} as Record<(typeof severityOrder)[number], NonNullable<typeof threats.data>>);

  return <>
    <TerminalHeader eyebrow="Triage Matrix / Priority Queue" title="Priority triage matrix" description="Records auto-refresh every 20 seconds. Priority remains source-grounded: severity is based on normalized scoring where supplied, while zero-day and exploitation wording is retained as a text-derived indicator." actions={<LiveSignal label="20s refresh" />} />
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
          </article>) : <EmptyTelemetry title={`No ${severity} records`} body="This tier contains no live records in the current retention window." />}
        </div>
      </section>)}
    </div>
    <div className="mt-5 flex items-center gap-2 border border-primary/20 bg-primary/5 px-3 py-2"><RefreshCw className="h-3.5 w-3.5 text-primary" /><p className="font-mono text-[10px] uppercase tracking-[0.15em] text-muted-foreground">Live query status: {threats.isFetching ? "refreshing" : "synchronized"}</p></div>
  </>;
}
