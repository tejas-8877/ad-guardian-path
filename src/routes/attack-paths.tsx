import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import { ArrowRight } from "lucide-react";
import { AppShell } from "@/components/adshield/AppShell";
import { Panel, SeverityBadge } from "@/components/adshield/ui-bits";
import { ATTACK_PATHS } from "@/lib/adshield/data";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/attack-paths")({
  head: () => ({
    meta: [
      { title: "Attack Paths — ADShield" },
      {
        name: "description",
        content:
          "Shortest-path analysis from ordinary principals to Tier-0 assets across DACL and session edges.",
      },
      { property: "og:title", content: "Attack Paths — ADShield" },
      { property: "og:description", content: "Tier-0 escalation chains ranked by traversal cost." },
    ],
  }),
  component: AttackPathsPage,
});

function AttackPathsPage() {
  const [activeId, setActiveId] = useState(ATTACK_PATHS[0]?.id ?? "");
  const active = ATTACK_PATHS.find((p) => p.id === activeId) ?? ATTACK_PATHS[0];

  return (
    <AppShell
      title="Attack Paths"
      subtitle="Dijkstra traversal over MemberOf, ACL, delegation and session edges"
      requiredPermission="view:attack_paths"
    >
      <div className="grid gap-4 lg:grid-cols-3">
        <Panel title={`${ATTACK_PATHS.length} Tier-0 paths`}>
          <ul className="space-y-2">
            {ATTACK_PATHS.map((p) => (
              <li key={p.id}>
                <button
                  onClick={() => setActiveId(p.id)}
                  className={cn(
                    "w-full rounded-md border px-3 py-2 text-left transition-colors",
                    p.id === active.id
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
        </Panel>

        <Panel title="Path detail" className="lg:col-span-2">
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
              <li key={`${s.sourceName}-${s.targetName}-${i}`} className="relative pl-8">
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
                </div>
              </li>
            ))}
          </ol>

          <div className="rounded-md border border-severity-critical/40 bg-severity-critical/10 p-3 text-sm">
            <p className="font-medium text-severity-critical">Recommended break point</p>
            <p className="mt-1 text-muted-foreground">
              Remove the{" "}
              <span className="font-mono">{highestCost(active.steps).edgeType}</span> edge between{" "}
              <span className="font-mono">{highestCost(active.steps).sourceName}</span> and{" "}
              <span className="font-mono">{highestCost(active.steps).targetName}</span> — it carries
              the highest traversal cost and severs this chain.
            </p>
          </div>
        </Panel>
      </div>
    </AppShell>
  );
}

function highestCost(steps: { sourceName: string; targetName: string; edgeType: string; cost: number }[]) {
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
};

function describe(edge: string) {
  return EDGE_DESCRIPTIONS[edge] ?? "Directory relationship";
}
