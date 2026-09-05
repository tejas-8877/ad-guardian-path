import { createFileRoute } from "@tanstack/react-router";
import { useMemo, useState } from "react";
import { ArrowRight, FlaskConical, RotateCcw, Scissors, ShieldCheck } from "lucide-react";
import { AppShell } from "@/components/adshield/AppShell";
import { DemoBadge, ErrorBlock, LoadingBlock } from "@/components/adshield/states";
import { Panel, SeverityBadge, StatTile } from "@/components/adshield/ui-bits";
import { useLive } from "@/lib/adshield/auth";
import { FINDINGS } from "@/lib/adshield/data";
import { useBackendGraph, useFindings } from "@/lib/adshield/hooks";
import {
  edgeId,
  liveGraph,
  measure,
  simulateRemoval,
  SIMULATION_NOTICE,
  type GraphPath,
  type GraphStep,
} from "@/lib/adshield/graph";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/attack-paths")({
  head: () => ({
    meta: [
      { title: "Attack Paths & Remediation Simulator — ADShield" },
      {
        name: "description",
        content:
          "Shortest-path analysis to Tier-0 assets with a non-mutating remediation simulator that models edge removal before you touch Active Directory.",
      },
      { property: "og:title", content: "Attack Paths & Remediation Simulator — ADShield" },
      {
        property: "og:description",
        content: "Model the blast-radius impact of removing a privilege edge without changing AD.",
      },
    ],
  }),
  component: AttackPathsPage,
});

const EMPTY_GRAPH = new AttackGraph([], []);

function AttackPathsPage() {
  const [removed, setRemoved] = useState<string[]>([]);
  const [activeId, setActiveId] = useState<string | null>(null);
  const live = useLive();
  const graphQuery = useBackendGraph();
  const findingsQuery = useFindings();

  const ready = live ? !!graphQuery.data && !!findingsQuery.data : true;
  const source = live ? (graphQuery.data ?? EMPTY_GRAPH) : liveGraph;
  const findings = live ? (findingsQuery.data ?? []) : FINDINGS;

  const baseline = useMemo(() => measure(source, findings), [source, findings]);
  const simulation = useMemo(
    () =>
      removed.length
        ? simulateRemoval(source, removed, "Analyst remediation candidate", findings)
        : null,
    [source, findings, removed],
  );

  const graph = useMemo(() => (removed.length ? source.without(removed) : source), [source, removed]);
  const paths = useMemo(() => graph.allTier0Paths(12), [graph]);
  const eliminated = simulation?.eliminatedPaths ?? [];

  const active: GraphPath | undefined = paths.find((p) => p.id === activeId) ?? paths[0];
  const metrics = simulation ? simulation.after : baseline;

  const toggle = (step: GraphStep) => {
    const id = `${step.sourceSid}|${step.edgeType}|${step.targetSid}`;
    setRemoved((prev) => (prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id]));
  };

  const error = graphQuery.error ?? findingsQuery.error;

  return (
    <AppShell
      title="Attack Paths"
      subtitle="Dijkstra traversal over MemberOf, ACL, delegation and session edges"
      requiredPermission="view:attack_paths"
    >
      {!live && <DemoBadge className="mb-4" />}
      {live && !ready && !error && <LoadingBlock label="Building the attack graph from the backend…" />}
      {live && error && (
        <ErrorBlock
          error={error}
          onRetry={() => {
            void graphQuery.refetch();
            void findingsQuery.refetch();
          }}
        />
      )}
      {ready && (
      <>
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatTile
          label="Domain risk score"
          value={metrics.riskScore}
          tone={simulation && simulation.riskReduction > 0 ? "primary" : "critical"}
          hint={
            simulation
              ? `${simulation.riskReduction >= 0 ? "−" : "+"}${Math.abs(simulation.riskReduction)} vs baseline ${baseline.riskScore}`
              : "Findings + graph exposure"
          }
        />
        <StatTile
          label="Tier-0 paths"
          value={metrics.attackPaths}
          hint={simulation ? `${simulation.pathsEliminated} eliminated by simulation` : "Reachable escalations"}
        />
        <StatTile
          label="Exposed principals"
          value={metrics.tier0Exposure}
          hint={`${metrics.reachablePrivileged} privileged targets reachable`}
        />
        <StatTile
          label="Shortest chain"
          value={metrics.shortestPathHops ?? "—"}
          hint={`avg traversal cost ${metrics.averagePathCost}`}
        />
      </div>

      {simulation && (
        <div className="mt-4 rounded-lg border border-primary/40 bg-primary/10 p-4">
          <div className="flex flex-wrap items-center gap-2">
            <FlaskConical className="size-4 text-primary" />
            <p className="font-mono text-xs uppercase tracking-widest text-primary">
              {SIMULATION_NOTICE}
            </p>
            <button
              onClick={() => setRemoved([])}
              className="ml-auto inline-flex items-center gap-2 rounded-md border border-border px-3 py-1.5 text-xs text-muted-foreground transition-colors hover:text-foreground"
            >
              <RotateCcw className="size-3.5" /> Reset simulation
            </button>
          </div>
          <div className="mt-3 grid gap-3 md:grid-cols-3">
            <SimStat label="Risk reduction" value={`${simulation.riskReduction} pts`} sub={`${simulation.riskReductionPct}%`} />
            <SimStat label="Paths eliminated" value={simulation.pathsEliminated} sub={`${simulation.remainingPaths.length} remaining`} />
            <SimStat
              label="Exposure reduction"
              value={simulation.tier0ExposureReduction}
              sub={`${simulation.removedEdges.length} edge(s) modelled`}
            />
          </div>
          <ul className="mt-3 space-y-1">
            {simulation.removedEdges.map((e) => (
              <li key={edgeId(e)} className="font-mono text-[11px] text-muted-foreground">
                <Scissors className="mr-1 inline size-3 text-severity-high" />
                {liveGraph.name(e.sourceSid)} —{e.edgeType}→ {liveGraph.name(e.targetSid)}
              </li>
            ))}
          </ul>
          {eliminated.length > 0 && (
            <p className="mt-3 text-xs text-severity-low">
              Severed chains: {eliminated.map((p) => `${p.sourceName} → ${p.targetName}`).join(", ")}
            </p>
          )}
        </div>
      )}

      <div className="mt-4 grid gap-4 lg:grid-cols-3">
        <Panel title={`${paths.length} Tier-0 paths`}>
          {paths.length === 0 ? (
            <p className="flex items-center gap-2 text-sm text-severity-low">
              <ShieldCheck className="size-4" /> No Tier-0 path remains in this simulation.
            </p>
          ) : (
            <ul className="space-y-2">
              {paths.map((p) => (
                <li key={p.id}>
                  <button
                    onClick={() => setActiveId(p.id)}
                    className={cn(
                      "w-full rounded-md border px-3 py-2 text-left transition-colors",
                      p.id === active?.id
                        ? "border-primary bg-sidebar-accent"
                        : "border-border hover:bg-sidebar-accent",
                    )}
                  >
                    <div className="flex items-center gap-2">
                      <SeverityBadge severity={p.severity} />
                      <span className="ml-auto font-mono text-[10px] text-muted-foreground">
                        cost {p.totalCost}
                      </span>
                    </div>
                    <p className="mt-2 font-mono text-xs">
                      {p.sourceName} → <span className="text-severity-critical">{p.targetName}</span>
                    </p>
                    <p className="mt-1 text-[11px] text-muted-foreground">{p.hops} hops</p>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </Panel>

        <Panel title="Path detail — click an edge to simulate its removal" className="lg:col-span-2">
          {!active ? (
            <p className="text-sm text-muted-foreground">
              Every modelled escalation chain is severed. Reset the simulation to review the live graph.
            </p>
          ) : (
            <>
              <div className="flex flex-wrap items-center gap-2">
                <SeverityBadge severity={active.severity} />
                <span className="font-mono text-sm">{active.sourceName}</span>
                <ArrowRight className="size-4 text-muted-foreground" />
                <span className="font-mono text-sm text-severity-critical">{active.targetName}</span>
                <span className="ml-auto font-mono text-xs text-muted-foreground">
                  {active.hops} hops · total cost {active.totalCost}
                </span>
              </div>

              <ol className="mt-6 space-y-0">
                {active.steps.map((s, i) => (
                  <li key={`${s.sourceSid}-${s.targetSid}-${i}`} className="relative pl-8">
                    <span className="absolute left-2 top-1 size-3 rounded-full border-2 border-primary bg-background" />
                    {i < active.steps.length - 1 && (
                      <span className="absolute left-[13px] top-4 h-full w-px bg-border" />
                    )}
                    <div className="pb-6">
                      <p className="font-mono text-sm">
                        {s.sourceName}{" "}
                        <span className="rounded border border-primary/40 bg-primary/10 px-1.5 py-0.5 text-[10px] uppercase tracking-wider text-primary">
                          {s.edgeType}
                        </span>{" "}
                        {s.targetName}
                      </p>
                      <p className="mt-1 text-xs text-muted-foreground">
                        {describe(s.edgeType)} · edge cost {s.cost}
                      </p>
                      <button
                        onClick={() => toggle(s)}
                        className="mt-2 inline-flex items-center gap-1.5 rounded-md border border-border px-2 py-1 text-[11px] text-muted-foreground transition-colors hover:border-severity-high hover:text-severity-high"
                      >
                        <Scissors className="size-3" /> Simulate removal
                      </button>
                    </div>
                  </li>
                ))}
              </ol>

              <div className="rounded-md border border-severity-critical/40 bg-severity-critical/10 p-3 text-sm">
                <p className="font-medium text-severity-critical">Recommended break point</p>
                <p className="mt-1 text-muted-foreground">
                  Remove the <span className="font-mono">{highestCost(active.steps).edgeType}</span>{" "}
                  edge between{" "}
                  <span className="font-mono">{highestCost(active.steps).sourceName}</span> and{" "}
                  <span className="font-mono">{highestCost(active.steps).targetName}</span> — it
                  carries the highest traversal cost and severs this chain.
                </p>
                <button
                  onClick={() => toggle(highestCost(active.steps))}
                  className="mt-3 inline-flex items-center gap-2 rounded-md border border-severity-critical/50 px-3 py-1.5 text-xs text-severity-critical"
                >
                  <FlaskConical className="size-3.5" /> Simulate this remediation
                </button>
              </div>
            </>
          )}
        </Panel>
      </div>
    </AppShell>
  );
}

function SimStat({ label, value, sub }: { label: string; value: string | number; sub: string }) {
  return (
    <div className="rounded-md border border-border bg-card/60 p-3">
      <p className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">{label}</p>
      <p className="mt-1 text-2xl font-semibold tabular-nums text-primary">{value}</p>
      <p className="text-[11px] text-muted-foreground">{sub}</p>
    </div>
  );
}

function highestCost(steps: GraphStep[]) {
  return steps.reduce((a, b) => (b.cost > a.cost ? b : a));
}

const EDGE_DESCRIPTIONS: Record<string, string> = {
  MemberOf: "Inherits every right granted to the target group",
  ForceChangePassword: "Can reset the target's password without knowing the old one",
  GenericAll: "Full control over the target object",
  GenericWrite: "Can write attributes, e.g. add an SPN for targeted Kerberoasting",
  WriteDacl: "Can rewrite the target's ACL and grant itself full control",
  AdminTo: "Local administrator on the target host",
  CanRDP: "Interactive logon rights to the target host",
  HasSession: "A privileged session is present and its credentials can be harvested",
  HasDCSync: "Can replicate directory secrets (DCSync)",
  AllowedToDelegate: "Can impersonate users to the target service",
  GpLink: "Policy applied to the target — write access means code execution",
};

function describe(edge: string) {
  return EDGE_DESCRIPTIONS[edge] ?? "Directory relationship";
}
