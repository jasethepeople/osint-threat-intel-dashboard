import { EmptyTelemetry, LiveSignal, PanelTitle, TerminalHeader, dateTime } from "@/components/threat-ui";
import { Input } from "@/components/ui/input";
import { trpc } from "@/lib/trpc";
import { CheckCircle2, Fingerprint, ShieldAlert } from "lucide-react";
import { useState } from "react";

export default function AuditLog() {
  const audit = trpc.intelligence.audit.useQuery({ limit: 160 }, { refetchInterval: 20_000 });
  const [filter, setFilter] = useState("");
  const integrity = audit.data?.integrity;
  const events = (audit.data?.events ?? []).filter(event => `${event.eventType} ${event.entityType} ${event.entityId ?? ""} ${JSON.stringify(event.payload)}`.toLowerCase().includes(filter.trim().toLowerCase()));
  return <>
    <TerminalHeader eyebrow="Audit Log / Integrity Chain" title="Tamper-evident operational log" description="Every dashboard action, source synchronization, extraction result, LLM brief, and critical notification is appended to a SHA-256 hash chain. Verification recomputes the chain against immutable event fields at read time." actions={<LiveSignal label="chain verification" />} />
    <section className="mb-6 grid gap-4 md:grid-cols-3"><div className="terminal-panel p-4"><p className="terminal-kicker">Chain status</p><div className="mt-3 flex items-center gap-3">{integrity?.valid ? <CheckCircle2 className="h-7 w-7 text-primary" /> : <ShieldAlert className="h-7 w-7 text-destructive" />}<p className={integrity?.valid ? "font-mono text-lg font-semibold text-primary" : "font-mono text-lg font-semibold text-destructive"}>{integrity?.valid ? "VERIFIED" : "UNVERIFIED"}</p></div></div><div className="terminal-panel p-4"><p className="terminal-kicker">Entries checked</p><p className="mt-4 font-mono text-3xl font-semibold text-foreground">{integrity?.checked ?? 0}</p></div><div className="terminal-panel p-4"><p className="terminal-kicker">Integrity method</p><div className="mt-3 flex items-center gap-2"><Fingerprint className="h-4 w-4 text-primary" /><p className="font-mono text-xs text-foreground">SHA-256 chained events</p></div></div></section>
    <section className="terminal-panel p-4 md:p-5"><PanelTitle label="Append-only ledger" title="Recent operational events" right={<span className="font-mono text-[10px] text-muted-foreground">{audit.data?.events.length ?? 0} events</span>} />
      <Input value={filter} onChange={event => setFilter(event.target.value)} placeholder="Filter event type, entity, or payload" className="mb-4 h-9 rounded-none border-primary/25 bg-black/30 font-mono text-xs" />
      {audit.isLoading ? <div className="h-64 animate-pulse bg-muted/30" /> : audit.error ? <EmptyTelemetry title="Audit ledger unavailable" body={audit.error.message} /> : events.length ? <div className="space-y-2">{events.map(event => <article key={event.id} className="grid gap-2 border border-border/80 bg-black/15 p-3 md:grid-cols-[142px_200px_minmax(0,1fr)_120px]"><p className="font-mono text-[10px] text-muted-foreground">{dateTime(event.createdAt)}</p><p className="font-mono text-[10px] font-semibold uppercase tracking-wider text-primary">{event.eventType}</p><p className="font-mono text-[10px] leading-5 text-muted-foreground">{event.entityType}{event.entityId ? ` · ${event.entityId}` : ""}<br />{JSON.stringify(event.payload)}</p><p className="truncate font-mono text-[9px] text-muted-foreground" title={event.eventHash}>{event.eventHash.slice(0, 14)}…</p></article>)}</div> : <EmptyTelemetry title={audit.data?.events.length ? "No events match this filter" : "Ledger initialized"} body={audit.data?.events.length ? "Adjust the filter to view a different audit slice." : "Events begin once a user runs an intelligence source or configures its schedule. The audit chain intentionally contains no seeded records."} />}
    </section>
  </>;
}
