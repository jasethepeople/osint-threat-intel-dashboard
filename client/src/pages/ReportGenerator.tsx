import { EmptyTelemetry, LiveSignal, PanelTitle, SeverityBadge, TerminalHeader, dateTime } from "@/components/threat-ui";
import { Button } from "@/components/ui/button";
import { trpc } from "@/lib/trpc";
import { jsPDF } from "jspdf";
import { BrainCircuit, FileDown, Loader2 } from "lucide-react";
import { toast } from "sonner";
import { buildReportPayload } from "@shared/report";

export default function ReportGenerator() {
  const counts = trpc.intelligence.overview.useQuery(undefined, { refetchInterval: 30_000 });
  const threats = trpc.intelligence.threats.useQuery({ limit: 20 }, { refetchInterval: 30_000 });
  const audit = trpc.intelligence.audit.useQuery({ limit: 10 }, { refetchInterval: 30_000 });
  const digest = trpc.intelligence.generateDailyDigest.useMutation({ onError: error => toast.error(error.message) });
  const exportPdf = () => {
    const doc = new jsPDF({ unit: "pt", format: "letter" });
    let y = 54;
    const write = (value: string, size = 9, color: [number, number, number] = [40, 31, 17]) => {
      doc.setFont("courier", "normal"); doc.setFontSize(size); doc.setTextColor(...color);
      const lines = doc.splitTextToSize(value, 500);
      if (y + lines.length * (size + 3) > 742) { doc.addPage(); y = 54; }
      doc.text(lines, 54, y); y += lines.length * (size + 3) + 9;
    };
    doc.setFillColor(16, 13, 8); doc.rect(0, 0, 612, 792, "F");
    doc.setFont("courier", "bold"); doc.setFontSize(18); doc.setTextColor(245, 158, 11); doc.text("SENTINEL ATLAS // INTELLIGENCE REPORT", 54, y); y += 28;
    write(`Generated: ${new Date().toLocaleString()} | Source-grounded public intelligence`, 8, [210, 195, 166]);
    const value = counts.data?.counts ?? { Critical: 0, High: 0, Medium: 0, Low: 0, total: 0 };
    const payload = buildReportPayload({ generatedAt: new Date(), counts: value, dailyDigest: digest.data?.digest, threats: (threats.data ?? []).map(threat => ({ identifier: threat.cveId ?? threat.ghsaId ?? "NEWS", severity: threat.severity, cvssScore: threat.cvssScore, title: threat.title, sourceUrl: threat.sourceUrl })), auditEvents: audit.data?.events ?? [] });
    write(`TRIAGE SNAPSHOT  Critical: ${payload.triage.Critical}  High: ${payload.triage.High}  Medium: ${payload.triage.Medium}  Low: ${payload.triage.Low}`, 10, [245, 158, 11]);
    write("DAILY ANALYST DIGEST", 11, [245, 158, 11]); write(payload.dailyDigest, 9, [238, 227, 204]);
    write("TOP RETAINED RECORDS", 11, [245, 158, 11]);
    payload.topThreats.forEach(threat => write(`${threat.identifier} [${threat.severity}] CVSS ${threat.cvssScore ?? "—"}\n${threat.title}\nSource: ${threat.sourceUrl}`, 8, [238, 227, 204]));
    write("AUDIT LOG EXCERPT", 11, [245, 158, 11]);
    payload.auditExcerpt.forEach(event => write(`${dateTime(event.createdAt)}  ${event.eventType}  ${event.eventHash}…`, 8, [210, 195, 166]));
    doc.save(`sentinel-atlas-intelligence-${new Date().toISOString().slice(0, 10)}.pdf`);
    toast.success("PDF intelligence report downloaded.");
  };
  return <>
    <TerminalHeader eyebrow="Report Generator / Analyst Deliverable" title="Intelligence report generator" description="Build a local PDF from the current retained record set. The report includes a triage snapshot, top CVEs, a tamper-evident audit excerpt, and the inline LLM daily digest when generated." actions={<><LiveSignal label="snapshot ready" /><Button onClick={exportPdf} disabled={!threats.data?.length} className="rounded-none bg-primary font-mono text-xs uppercase tracking-wide text-primary-foreground hover:bg-primary/90"><FileDown className="mr-2 h-3.5 w-3.5" />Download PDF</Button></>} />
    <section className="terminal-panel mb-5 p-4 md:p-5"><PanelTitle label="Analyst operating protocol" title="Daily digest workflow" /><div className="grid gap-3 md:grid-cols-3">{[["01", "Synchronize", "Run all enabled sources or verify that scheduled jobs completed without errors."], ["02", "Triage", "Review Critical and High items, source provenance, watchlist matches, and the integrity-ledger excerpt."], ["03", "Brief & distribute", "Generate the source-grounded digest, review it inline, then download the PDF snapshot for distribution."]].map(([step, title, detail]) => <div key={step} className="border-l-2 border-primary/50 bg-black/15 p-3"><p className="font-mono text-[10px] font-semibold text-primary">{step}</p><p className="mt-1 font-mono text-xs font-semibold text-foreground">{title}</p><p className="mt-2 font-mono text-[10px] leading-5 text-muted-foreground">{detail}</p></div>)}</div></section>
    <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_360px]"><section className="terminal-panel p-4 md:p-5"><PanelTitle label="Inline LLM brief" title="Daily threat digest" right={<Button onClick={() => digest.mutate()} disabled={digest.isPending} variant="outline" className="h-8 rounded-none border-primary/40 px-3 font-mono text-[10px] uppercase tracking-wider text-primary hover:bg-primary/10">{digest.isPending ? <Loader2 className="mr-1.5 h-3 w-3 animate-spin" /> : <BrainCircuit className="mr-1.5 h-3 w-3" />}Generate digest</Button>} />
      {digest.data?.digest ? <div className="whitespace-pre-line border-l-2 border-primary bg-primary/5 p-4 font-mono text-xs leading-6 text-foreground/90">{digest.data.digest}</div> : <EmptyTelemetry title="No daily digest yet" body="Generate a concise analyst brief from the current source records. It appears here and is included in the PDF report." />}
    </section><aside className="terminal-panel p-4 md:p-5"><PanelTitle label="Report contents" title="Live inclusion set" /><div className="space-y-3">{(threats.data ?? []).slice(0, 6).map(threat => <div key={threat.id} className="border-l-2 border-primary/40 py-1 pl-3"><div className="flex items-center justify-between gap-2"><p className="font-mono text-[10px] font-semibold text-foreground">{threat.cveId ?? threat.ghsaId ?? "NEWS"}</p><SeverityBadge severity={threat.severity} /></div><p className="mt-1 line-clamp-2 font-mono text-[10px] leading-4 text-muted-foreground">{threat.title}</p></div>)}</div></aside></div>
  </>;
}
