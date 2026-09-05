import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import { AppShell } from "@/components/adshield/AppShell";
import { DemoBadge, ErrorBlock, LoadingBlock } from "@/components/adshield/states";
import { Panel, SeverityBadge } from "@/components/adshield/ui-bits";
import { useLive } from "@/lib/adshield/auth";
import { FINDINGS } from "@/lib/adshield/data";
import type { Severity } from "@/lib/adshield/data";
import { useFindings } from "@/lib/adshield/hooks";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/findings")({
  head: () => ({
    meta: [
      { title: "Misconfiguration Findings — ADShield" },
      {
        name: "description",
        content:
          "MITRE ATT&CK-mapped Active Directory misconfiguration findings with remediation guidance.",
      },
      { property: "og:title", content: "Misconfiguration Findings — ADShield" },
      {
        property: "og:description",
        content: "Kerberoasting, delegation and ACL findings with remediation steps.",
      },
    ],
  }),
  component: FindingsPage,
});

const FILTERS: (Severity | "all")[] = ["all", "critical", "high", "medium", "low"];

function FindingsPage() {
  const [severity, setSeverity] = useState<Severity | "all">("all");
  const [q, setQ] = useState("");
  const [open, setOpen] = useState<string | null>(null);
  const live = useLive();
  const query = useFindings();

  const source = live ? (query.data ?? []) : FINDINGS;
  const items = source.filter(
    (f) =>
      (severity === "all" || f.severity === severity) &&
      (q === "" ||
        `${f.title} ${f.rule} ${f.principalName}`.toLowerCase().includes(q.toLowerCase())),
  );

  return (
    <AppShell
      title="Findings"
      subtitle={
        live
          ? "Rule engine output from the backend — each finding maps to a MITRE ATT&CK technique"
          : "Fixture findings — the backend is not connected"
      }
      requiredPermission="view:findings"
    >
      {!live && <DemoBadge className="mb-4" />}
      {live && query.isPending && <LoadingBlock label="Loading findings from the backend…" />}
      {live && query.isError && (
        <ErrorBlock error={query.error} onRetry={() => void query.refetch()} />
      )}
      {(!live || query.isSuccess) && (
      <Panel
        action={
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Search rule or principal…"
            className="w-48 rounded-md border border-input bg-background px-2 py-1 text-xs outline-none focus:border-primary"
          />
        }
        title={`${items.length} findings`}
      >
        <div className="mb-4 flex flex-wrap gap-2">
          {FILTERS.map((f) => (
            <button
              key={f}
              onClick={() => setSeverity(f)}
              className={cn(
                "rounded-full border px-3 py-1 font-mono text-[10px] uppercase tracking-widest",
                severity === f
                  ? "border-primary text-primary"
                  : "border-border text-muted-foreground hover:text-foreground",
              )}
            >
              {f}
            </button>
          ))}
        </div>

        <ul className="space-y-2">
          {items.map((f) => {
            const expanded = open === f.id;
            return (
              <li key={f.id} className="rounded-md border border-border">
                <button
                  onClick={() => setOpen(expanded ? null : f.id)}
                  className="flex w-full flex-wrap items-center gap-3 px-3 py-3 text-left"
                >
                  <SeverityBadge severity={f.severity} />
                  <span className="text-sm font-medium">{f.title}</span>
                  <span className="font-mono text-xs text-muted-foreground">{f.principalName}</span>
                  <span className="ml-auto font-mono text-[10px] uppercase tracking-widest text-primary">
                    {f.mitre}
                  </span>
                </button>
                {expanded && (
                  <div className="border-t border-border px-3 py-3 text-sm">
                    <p className="text-muted-foreground">{f.description}</p>
                    <p className="mt-3 font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
                      Remediation
                    </p>
                    <p className="mt-1">{f.remediation}</p>
                    <p className="mt-3 font-mono text-[11px] text-muted-foreground">
                      rule={f.rule} · sid={f.principalSid}
                    </p>
                  </div>
                )}
              </li>
            );
          })}
          {items.length === 0 && (
            <li className="py-8 text-center text-sm text-muted-foreground">No findings match.</li>
          )}
        </ul>
      </Panel>
    </AppShell>
  );
}
