import ThreatMapView from "@/components/ThreatMapView";
import { EmptyTelemetry, LiveSignal, PanelTitle, SeverityBadge, TerminalHeader, dateTime } from "@/components/threat-ui";
import { Button } from "@/components/ui/button";
import { trpc } from "@/lib/trpc";
import { DatabaseZap, RefreshCw, ShieldAlert } from "lucide-react";
import { toast } from "sonner";

export default function Home() {
  const utils = trpc.useUtils();
  const overview = trpc.intelligence.overview.useQuery(undefined, { refetchInterval: 30_000 });
  const observations = trpc.intelligence.mapObservations.useQuery(undefined, { refetchInterval: 30_000 });
  const threats = trpc.intelligence.threats.useQuery({ limit: 6 }, { refetchInterval: 30_000 });
  const runAll = trpc.intelligence.runAllSources.useMutation({
    onSuccess: results => { toast.success(`Synchronization complete: ${results.length} source checks finished.`); void utils.intelligence.invalidate(); },
    onError: error => toast.error(error.message),
  });
  const counts = overview.data?.counts ?? { Critical: 0, High: 0, Medium: 0, Low: 0, total: 0 };

  return <>
    <TerminalHeader eyebrow="Threat Map / Global Surface" title="Global threat activity" description="Geographic observations are extracted from source-attributed public advisories and security news. Marker coordinates signal published geographic context, not attacker attribution." actions={<><LiveSignal /><Button onClick={() => runAll.mutate()} disabled={runAll.isPending} className="rounded-none bg-primary px-3 font-mono text-xs uppercase tracking-wide text-primary-foreground hover:bg-primary/90"><RefreshCw className={runAll.isPending ? "mr-2 h-3.5 w-3.5 animate-spin" : "mr-2 h-3.5 w-3.5"} />Sync live sources</Button></>} />

    <section className="mb-5 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
      {(["Critical", "High", "Medium", "Low"] as const).map(severity => <div key={severity} className="terminal-panel p-4"><div className="flex items-center justify-between"><SeverityBadge severity={severity} /><span className="font-mono text-2xl font-semibold text-foreground">{counts[severity]}</span></div><p className="mt-4 font-mono text-[10px] uppercase tracking-[0.18em] text-muted-foreground">Current queue</p></div>)}
    </section>

    <section className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_330px]">
      <div className="terminal-panel p-4 md:p-5"><PanelTitle label="Geo signal layer" title="Threat density map" right={<span className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">{observations.data?.length ?? 0} observations</span>} />
        {observations.isLoading ? <div className="h-[500px] animate-pulse bg-muted/30" /> : observations.data?.length ? <ThreatMapView observations={observations.data} /> : <EmptyTelemetry title="Awaiting geographic observations" body="Run a live synchronization. The map only renders country-level context that was actually found in ingested source text." />}
      </div>
      <aside className="terminal-panel p-4 md:p-5"><PanelTitle label="Telemetry" title="Latest intelligence" right={<DatabaseZap className="h-4 w-4 text-primary" />} />
        <div className="space-y-3">
          {threats.data?.length ? threats.data.map(threat => <div key={threat.id} className="border-l-2 border-primary/50 bg-black/15 p-3"><div className="flex items-start justify-between gap-2"><p className="font-mono text-xs font-semibold text-foreground">{threat.cveId ?? threat.ghsaId ?? "NEWS SIGNAL"}</p><SeverityBadge severity={threat.severity} /></div><p className="mt-2 line-clamp-2 font-mono text-[11px] leading-5 text-muted-foreground">{threat.title}</p><p className="mt-2 font-mono text-[10px] text-muted-foreground">{dateTime(threat.ingestionTimestamp)}</p></div>) : <EmptyTelemetry title="No current intelligence" body="No demonstration records are shown. Synchronize a live source to populate this queue." />}
        </div>
        <div className="mt-5 border-t border-primary/15 pt-4"><div className="flex items-center gap-2 text-muted-foreground"><ShieldAlert className="h-3.5 w-3.5 text-primary" /><span className="font-mono text-[10px] uppercase tracking-wide">{counts.total} retained source records</span></div></div>
      </aside>
    </section>
  </>;
}
