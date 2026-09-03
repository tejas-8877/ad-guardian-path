import { createFileRoute } from "@tanstack/react-router";
import { useMemo, useState } from "react";
import { ArrowRight, Crosshair, Laptop, ShieldAlert, ShieldCheck } from "lucide-react";
import { AppShell } from "@/components/adshield/AppShell";
import { Panel, StatTile } from "@/components/adshield/ui-bits";
import { ENDPOINTS, type EndpointRecord } from "@/lib/adshield/data";
import { analyzeEndpoint, liveGraph, type CompromiseImpact } from "@/lib/adshield/graph";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/compromise-impact")({
  head: () => ({
    meta: [
      { title: "Compromise Impact — ADShield" },
      {
        name: "description",
        content:
          "Correlate a compromised endpoint to its Active Directory identity and score the resulting blast radius and Tier-0 attack paths.",
      },
      { property: "og:title", content: "Compromise Impact — ADShield" },
      {
        property: "og:description",
        content: "Endpoint → identity → attack-path correlation for incident triage.",
      },
    ],
  }),
  component: CompromiseImpactPage,
});

const STATUS_TONE: Record<string, string> = {
  malicious: "border-severity-critical/50 bg-severity-critical/15 text-severity-critical",
  suspicious: "border-severity-high/50 bg-severity-high/15 text-severity-high",
  clean: "border-severity-low/50 bg-severity-low/15 text-severity-low",
  unknown: "border-border bg-muted/20 text-muted-foreground",
};

const RISK_TONE: Record<CompromiseImpact["risk"], string> = {
  CRITICAL: "text-severity-critical",
  HIGH: "text-severity-high",
  MEDIUM: "text-severity-medium",
  LOW: "text-severity-low",
};

function CompromiseImpactPage() {
  const [selected, setSelected] = useState<EndpointRecord>(ENDPOINTS[0]!);
  const [whatIf, setWhatIf] = useState(false);

  const impact = useMemo(
    () =>
      analyzeEndpoint(
        liveGraph,
        selected.hostname,
        whatIf ? "compromised" : selected.status,
        selected.loggedOnUser,
      ),
    [selected, whatIf],
  );

  return (
    <AppShell
      title="Compromise Impact"
      subtitle="Endpoint telemetry correlated to directory identity, blast radius and Tier-0 reachability"
      requiredPermission="view:attack_paths"
    >
      <div className="grid gap-4 lg:grid-cols-3">
        <Panel title="Endpoints">
          <ul className="space-y-2">
            {ENDPOINTS.map((e) => (
              <li key={e.endpointId}>
                <button
                  onClick={() => {
                    setSelected(e);
                    setWhatIf(false);
                  }}
                  className={cn(
                    "w-full rounded-md border px-3 py-2 text-left transition-colors",
                    e.endpointId === selected.endpointId
                      ? "border-primary bg-sidebar-accent"
                      : "border-border hover:bg-sidebar-accent",
                  )}
                >
                  <div className="flex items-center gap-2">
                    <Laptop className="size-4 text-muted-foreground" />
                    <span className="font-mono text-sm">{e.hostname}</span>
                    <span
                      className={cn(
                        "ml-auto rounded-full border px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider",
                        STATUS_TONE[e.status],
                      )}
                    >
                      {e.status}
                    </span>
                  </div>
                  <p className="mt-1 text-[11px] text-muted-foreground">
                    {e.os} · seen {e.lastSeen}
                  </p>
                  {e.detection && (
                    <p className="mt-1 text-[11px] text-severity-high">{e.detection}</p>
                  )}
                </button>
              </li>
            ))}
          </ul>
        </Panel>

        <div className="space-y-4 lg:col-span-2">
          <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
            <StatTile
              label="Impact score"
              value={impact.riskScore}
              tone={impact.risk === "LOW" ? "primary" : "critical"}
              hint={impact.risk}
            />
            <StatTile
              label="Blast radius"
              value={impact.blastRadius.total}
              hint={`${impact.blastRadius.users} users · ${impact.blastRadius.groups} groups · ${impact.blastRadius.computers} hosts`}
            />
            <StatTile
              label="Tier-0 reachable"
              value={impact.blastRadius.privilegedTargets}
              tone={impact.tier0Exposed ? "critical" : "default"}
              hint={impact.tier0Exposed ? "Domain takeover possible" : "No Tier-0 reachability"}
            />
            <StatTile
              label="Escalation chains"
              value={impact.attackPathCount}
              hint={
                impact.shortestPathHops !== null
                  ? `shortest ${impact.shortestPathHops} hops`
                  : "none observed"
              }
            />
          </div>

          <Panel
            title="Identity correlation"
            action={
              <button
                onClick={() => setWhatIf((v) => !v)}
                className={cn(
                  "inline-flex items-center gap-2 rounded-md border px-3 py-1.5 text-xs transition-colors",
                  whatIf
                    ? "border-severity-critical/60 text-severity-critical"
                    : "border-border text-muted-foreground hover:text-foreground",
                )}
              >
                <Crosshair className="size-3.5" />
                {whatIf ? "Exit what-if" : "What if this identity is compromised?"}
              </button>
            }
          >
            <div className="grid gap-3 sm:grid-cols-2">
              <Field label="Endpoint" value={impact.endpoint} />
              <Field label="Assessed status" value={whatIf ? "compromised (what-if)" : impact.status} />
              <Field label="Correlated identity" value={impact.identity ?? "—"} />
              <Field label="Correlation source" value={impact.identitySource} />
            </div>
            {impact.notes.length > 0 && (
              <ul className="mt-3 space-y-1">
                {impact.notes.map((n) => (
                  <li key={n} className="flex items-center gap-2 text-xs text-severity-medium">
                    <ShieldAlert className="size-3.5" /> {n}
                  </li>
                ))}
              </ul>
            )}
            {whatIf && (
              <p className="mt-3 rounded-md border border-primary/40 bg-primary/10 p-3 text-xs text-primary">
                ANALYSIS ONLY — no Active Directory or endpoint change was performed.
              </p>
            )}
          </Panel>

          <Panel title="Shortest path to Tier-0">
            {impact.shortestPath.length ? (
              <div className="flex flex-wrap items-center gap-2">
                {impact.shortestPath.map((node, i) => (
                  <span key={`${node}-${i}`} className="flex items-center gap-2">
                    <span
                      className={cn(
                        "rounded-md border px-2 py-1 font-mono text-xs",
                        i === impact.shortestPath.length - 1
                          ? "border-severity-critical/50 bg-severity-critical/10 text-severity-critical"
                          : "border-border",
                      )}
                    >
                      {node}
                    </span>
                    {i < impact.shortestPath.length - 1 && (
                      <ArrowRight className="size-3.5 text-muted-foreground" />
                    )}
                  </span>
                ))}
              </div>
            ) : (
              <p className="flex items-center gap-2 text-sm text-severity-low">
                <ShieldCheck className="size-4" /> This endpoint has no reachable Tier-0 path.
              </p>
            )}

            {impact.paths.length > 0 && (
              <ul className="mt-4 space-y-2">
                {impact.paths.map((p) => (
                  <li
                    key={p.id}
                    className="flex items-center gap-2 rounded-md border border-border px-3 py-2 font-mono text-xs"
                  >
                    <span>{p.sourceName}</span>
                    <ArrowRight className="size-3 text-muted-foreground" />
                    <span className="text-severity-critical">{p.targetName}</span>
                    <span className="ml-auto text-[10px] text-muted-foreground">
                      {p.hops} hops · cost {p.totalCost}
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </Panel>
        </div>
      </div>
    </AppShell>
  );
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-md border border-border bg-card/60 p-3">
      <p className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
        {label}
      </p>
      <p className="mt-1 font-mono text-sm">{value}</p>
    </div>
  );
}
