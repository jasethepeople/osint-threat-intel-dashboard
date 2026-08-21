import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { trpc } from "@/lib/trpc";
import { ArchiveRestore, Clock3, ShieldCheck, Trash2 } from "lucide-react";
import { useEffect, useState } from "react";
import { toast } from "sonner";
import { PanelTitle, dateTime } from "./threat-ui";

export default function RetentionControl() {
  const utils = trpc.useUtils();
  const policy = trpc.intelligence.retentionPolicy.useQuery();
  const [days, setDays] = useState(90);
  const [enabled, setEnabled] = useState(false);
  const [confirmation, setConfirmation] = useState("");
  useEffect(() => { if (policy.data) { setDays(policy.data.retentionDays); setEnabled(policy.data.enabled); } }, [policy.data]);
  const preview = trpc.intelligence.retentionPreview.useQuery({ retentionDays: days });
  const configure = trpc.intelligence.configureRetention.useMutation({ onSuccess: async () => { await Promise.all([utils.intelligence.retentionPolicy.invalidate(), utils.intelligence.retentionPreview.invalidate()]); toast.success("Retention policy saved."); }, onError: error => toast.error(error.message) });
  const purge = trpc.intelligence.runRetention.useMutation({ onSuccess: async outcome => { setConfirmation(""); await utils.intelligence.invalidate(); toast.success(`Retention run completed: ${outcome.purgedCount} threat records removed.`); }, onError: error => toast.error(error.message) });
  const activate = trpc.intelligence.activateRetentionSchedule.useMutation({ onSuccess: async () => { await utils.intelligence.retentionPolicy.invalidate(); toast.success("Nightly 03:00 UTC retention schedule activated."); }, onError: error => toast.error(error.message) });
  const save = () => { if (!Number.isInteger(days) || days < 30 || days > 730) return toast.error("Retention must be a whole number from 30 to 730 days."); configure.mutate({ retentionDays: days, enabled }); };
  const pending = policy.isLoading || preview.isLoading;
  return <section className="mb-6 terminal-panel p-4 md:p-5"><PanelTitle label="Data lifecycle" title="Aging intelligence retention" right={<ArchiveRestore className="h-4 w-4 text-primary" />} />
    <p className="mb-4 font-mono text-[10px] leading-5 text-muted-foreground">Retention permanently removes expired threat records and their geographic observations. The append-only audit ledger is never purged. Preview first, save the policy, then type <span className="text-primary">PURGE</span> for a one-time run.</p>
    <div className="grid gap-3 xl:grid-cols-[200px_auto_minmax(0,1fr)]"><Input value={String(days)} onChange={event => setDays(Number(event.target.value))} inputMode="numeric" aria-label="Retention days" className="h-9 rounded-none border-primary/25 bg-black/30 font-mono text-xs" /><label className="flex h-9 items-center gap-2 border border-primary/15 px-3 font-mono text-[10px] uppercase text-muted-foreground"><input type="checkbox" checked={enabled} onChange={event => setEnabled(event.target.checked)} className="accent-[#F59E0B]" />Enable policy</label><div className="flex flex-wrap gap-2"><Button onClick={save} disabled={configure.isPending} variant="outline" className="h-9 rounded-none border-primary/40 px-3 font-mono text-[10px] uppercase text-primary"><ShieldCheck className="mr-1.5 h-3.5 w-3.5" />Save policy</Button><Button onClick={() => activate.mutate()} disabled={activate.isPending || !enabled} variant="outline" className="h-9 rounded-none border-primary/40 px-3 font-mono text-[10px] uppercase text-primary"><Clock3 className="mr-1.5 h-3.5 w-3.5" />Activate nightly</Button></div></div>
    <div className="mt-4 grid gap-4 lg:grid-cols-[minmax(0,1fr)_360px]"><div className="border border-primary/20 bg-primary/[0.04] p-3"><p className="font-mono text-[10px] uppercase tracking-wider text-primary">Preview</p><p className="mt-2 font-mono text-sm font-semibold text-foreground">{pending ? "Calculating aged records…" : `${preview.data?.candidateCount ?? 0} threat records eligible for removal`}</p><p className="mt-1 font-mono text-[10px] leading-5 text-muted-foreground">Cutoff: {preview.data ? dateTime(preview.data.cutoff) : "—"} · Oldest candidate: {preview.data?.oldestIngestionAt ? dateTime(preview.data.oldestIngestionAt) : "—"}</p><p className="mt-3 font-mono text-[10px] text-muted-foreground">Last policy run: {policy.data?.lastRunAt ? dateTime(policy.data.lastRunAt) : "never"} · Last removed: {policy.data?.lastPurgedCount ?? 0}</p></div><div className="border border-destructive/30 bg-destructive/[0.035] p-3"><p className="font-mono text-[10px] uppercase tracking-wider text-destructive">Manual run</p><div className="mt-2 flex gap-2"><Input value={confirmation} onChange={event => setConfirmation(event.target.value.toUpperCase())} placeholder="Type PURGE" className="h-8 rounded-none border-destructive/35 bg-black/30 font-mono text-xs" /><Button onClick={() => purge.mutate({ confirmation: "PURGE" })} disabled={confirmation !== "PURGE" || !enabled || purge.isPending} className="h-8 rounded-none bg-destructive px-3 font-mono text-[10px] uppercase text-white hover:bg-destructive/90"><Trash2 className="mr-1 h-3.5 w-3.5" />Run</Button></div><p className="mt-2 font-mono text-[9px] leading-4 text-muted-foreground">Nightly activation requires a published dashboard and schedules 03:00 UTC through the managed job service.</p></div></div>
  </section>;
}
