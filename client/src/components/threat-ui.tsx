import { cn } from "@/lib/utils";
import { AlertTriangle, CircleCheck, Crosshair, Radio } from "lucide-react";
import type { ReactNode } from "react";

export const severityOrder = ["Critical", "High", "Medium", "Low"] as const;

export function SeverityBadge({ severity }: { severity: string }) {
  const normalized = severity.toLowerCase();
  const label = severity === "Critical" ? "Critical" : severity === "High" ? "High" : severity === "Medium" ? "Medium" : "Low";
  return <span className={cn("inline-flex items-center gap-1 border px-2 py-1 font-mono text-[10px] font-semibold uppercase tracking-[0.15em]", `status-${normalized}`)}>{label === "Critical" ? <AlertTriangle className="h-3 w-3" /> : <CircleCheck className="h-3 w-3" />}{label}</span>;
}

export function TerminalHeader({ eyebrow, title, description, actions }: { eyebrow: string; title: string; description: string; actions?: ReactNode }) {
  return <header className="mb-6 flex flex-col gap-4 border-b border-primary/20 pb-5 lg:flex-row lg:items-end lg:justify-between">
    <div>
      <p className="terminal-kicker">{eyebrow}</p>
      <h1 className="terminal-heading mt-2">{title}</h1>
      <p className="mt-2 max-w-3xl font-mono text-xs leading-6 text-muted-foreground">{description}</p>
    </div>
    {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
  </header>;
}

export function PanelTitle({ label, title, right }: { label: string; title: string; right?: ReactNode }) {
  return <div className="mb-4 flex items-start justify-between gap-3 border-b border-primary/15 pb-3">
    <div>
      <p className="terminal-kicker">{label}</p>
      <h2 className="mt-1 font-mono text-sm font-semibold tracking-wide text-foreground">{title}</h2>
    </div>
    {right}
  </div>;
}

export function LiveSignal({ label = "Live telemetry" }: { label?: string }) {
  return <span className="inline-flex items-center gap-2 font-mono text-[10px] uppercase tracking-[0.16em] text-primary"><Radio className="terminal-pulse h-3 w-3" />{label}</span>;
}

export function EmptyTelemetry({ title, body }: { title: string; body: string }) {
  return <div className="flex min-h-48 flex-col items-center justify-center border border-dashed border-primary/30 bg-black/10 px-6 text-center">
    <Crosshair className="mb-3 h-5 w-5 text-primary" />
    <p className="font-mono text-xs font-semibold uppercase tracking-[0.14em] text-foreground">{title}</p>
    <p className="mt-2 max-w-md font-mono text-xs leading-5 text-muted-foreground">{body}</p>
  </div>;
}

export function dateTime(value?: Date | string | null) {
  if (!value) return "—";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? "—" : parsed.toLocaleString([], { month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit" });
}
