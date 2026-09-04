import { createFileRoute, Link } from "@tanstack/react-router";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { AppShell } from "@/components/adshield/AppShell";
import { DemoBadge, ErrorBlock, LoadingBlock } from "@/components/adshield/states";
import { Panel, SeverityBadge, StatTile } from "@/components/adshield/ui-bits";
import { toAttackPath } from "@/lib/adshield/api";
import { useLive } from "@/lib/adshield/auth";
import { ATTACK_PATHS, FINDINGS, PRINCIPALS, RISK_TREND } from "@/lib/adshield/data";
import type { AttackPath, Severity } from "@/lib/adshield/data";
import { useDashboard } from "@/lib/adshield/hooks";

export const Route = createFileRoute("/dashboard")({
  head: () => ({
    meta: [
      { title: "Security Overview — ADShield" },
      {
        name: "description",
        content: "Domain risk score, finding severity breakdown and critical Tier-0 attack paths.",
      },
      { property: "og:title", content: "Security Overview — ADShield" },
      { property: "og:description", content: "Domain risk posture at a glance for corp.local." },
    ],
  }),
  component: DashboardPage,
});

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];

interface Overview {
  domain: string;
  risk: number;
  users: number;
  groups: number;
  computers: number;
  objects: number;
  findingsTotal: number;
  bySeverity: { severity: Severity; count: number }[];
  tier0Exposed: number;
  paths: AttackPath[];
  topRules: [string, number][];
}

function fixtureOverview(): Overview {
  const bySeverity = SEVERITIES.map((s) => ({
    severity: s,
    count: FINDINGS.filter((f) => f.severity === s).length,
  }));
  const counts = (t: string) => PRINCIPALS.filter((p) => p.type === t).length;
  const topRules = Object.entries(
    FINDINGS.reduce<Record<string, number>>((acc, f) => {
      acc[f.rule] = (acc[f.rule] ?? 0) + 1;
      return acc;
    }, {}),
  )
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6) as [string, number][];

  return {
    domain: "corp.local",
    risk: RISK_TREND[RISK_TREND.length - 1]?.score ?? 0,
    users: counts("user"),
    groups: counts("group"),
    computers: counts("computer"),
    objects: PRINCIPALS.length,
    findingsTotal: FINDINGS.length,
    bySeverity,
    tier0Exposed: ATTACK_PATHS.length,
    paths: ATTACK_PATHS,
    topRules,
  };
}

function DashboardPage() {
  const live = useLive();
  const query = useDashboard();

  let overview: Overview | null = null;
  if (live && query.data) {
    const d = query.data;
    overview = {
      domain: d.domain,
      risk: d.risk_score,
      users: d.users,
      groups: d.groups,
      computers: d.computers,
      objects: d.users + d.groups + d.computers + d.gpos,
      findingsTotal:
        d.findings_by_severity.critical +
        d.findings_by_severity.high +
        d.findings_by_severity.medium +
        d.findings_by_severity.low,
      bySeverity: SEVERITIES.map((s) => ({ severity: s, count: d.findings_by_severity[s] })),
      tier0Exposed: d.tier0_exposed_principals,
      paths: d.critical_paths.map(toAttackPath),
      topRules: d.top_rules.map((r) => [r.rule, r.count] as [string, number]),
    };
  } else if (!live) {
    overview = fixtureOverview();
  }

  return (
    <AppShell
      title="Security Overview"
      subtitle={
        live
          ? "Latest backend collection — LDAP + DACL enumeration"
          : "Fixture snapshot — the backend is not connected"
      }
      requiredPermission="view:findings"
    >
      {!live && <DemoBadge className="mb-4" />}
      {live && query.isPending && <LoadingBlock label="Loading dashboard from the backend…" />}
      {live && query.isError && <ErrorBlock error={query.error} onRetry={() => void query.refetch()} />}

      {overview && (
        <>
          <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
            <StatTile
              label="Domain risk score"
              value={overview.risk}
              tone="critical"
              hint="0 = clean, 100 = critical"
            />
            <StatTile
              label="Open findings"
              value={overview.findingsTotal}
              hint={`${overview.bySeverity[0]?.count ?? 0} critical`}
            />
            <StatTile
              label="Tier-0 exposure"
              value={overview.tier0Exposed}
              tone="primary"
              hint="Principals with a path to Tier-0"
            />
            <StatTile
              label="Objects collected"
              value={overview.objects}
              hint={`${overview.users} users · ${overview.computers} hosts · ${overview.groups} groups`}
            />
          </div>

          <div className="mt-4 grid gap-4 lg:grid-cols-3">
            <Panel title="Risk trend (8 weeks, historical baseline)" className="lg:col-span-2">
              <div className="h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={RISK_TREND}>
                    <defs>
                      <linearGradient id="riskFill" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="var(--color-primary)" stopOpacity={0.5} />
                        <stop offset="100%" stopColor="var(--color-primary)" stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid stroke="var(--color-border)" strokeDasharray="3 3" vertical={false} />
                    <XAxis dataKey="week" stroke="var(--color-muted-foreground)" fontSize={11} tickLine={false} />
                    <YAxis stroke="var(--color-muted-foreground)" fontSize={11} tickLine={false} axisLine={false} />
                    <Tooltip
                      contentStyle={{
                        background: "var(--color-card)",
                        border: "1px solid var(--color-border)",
                        borderRadius: 8,
                        fontSize: 12,
                      }}
                    />
                    <Area
                      type="monotone"
                      dataKey="score"
                      stroke="var(--color-primary)"
                      strokeWidth={2}
                      fill="url(#riskFill)"
                    />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </Panel>

            <Panel title="Findings by severity">
              <div className="h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={overview.bySeverity}>
                    <CartesianGrid stroke="var(--color-border)" strokeDasharray="3 3" vertical={false} />
                    <XAxis dataKey="severity" stroke="var(--color-muted-foreground)" fontSize={11} tickLine={false} />
                    <YAxis allowDecimals={false} stroke="var(--color-muted-foreground)" fontSize={11} axisLine={false} tickLine={false} />
                    <Tooltip
                      cursor={{ fill: "var(--color-sidebar-accent)" }}
                      contentStyle={{
                        background: "var(--color-card)",
                        border: "1px solid var(--color-border)",
                        borderRadius: 8,
                        fontSize: 12,
                      }}
                    />
                    <Bar dataKey="count" fill="var(--color-primary)" radius={[4, 4, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </Panel>
          </div>

          <div className="mt-4 grid gap-4 lg:grid-cols-3">
            <Panel
              title="Critical attack paths"
              className="lg:col-span-2"
              action={
                <Link to="/attack-paths" className="text-xs text-primary hover:underline">
                  View all
                </Link>
              }
            >
              <ul className="space-y-3">
                {overview.paths.slice(0, 4).map((p) => (
                  <li key={p.id} className="rounded-md border border-border p-3">
                    <div className="flex flex-wrap items-center gap-2">
                      <SeverityBadge severity={p.severity} />
                      <span className="font-mono text-sm">{p.sourceName}</span>
                      <span className="text-muted-foreground">→</span>
                      <span className="font-mono text-sm text-severity-critical">{p.targetName}</span>
                      <span className="ml-auto font-mono text-xs text-muted-foreground">
                        {p.hops} hops · cost {p.totalCost}
                      </span>
                    </div>
                    <p className="mt-2 font-mono text-[11px] text-muted-foreground">
                      {p.steps.map((s) => s.edgeType).join(" → ")}
                    </p>
                  </li>
                ))}
                {overview.paths.length === 0 && (
                  <li className="py-6 text-center text-sm text-muted-foreground">
                    No Tier-0 paths in the current snapshot.
                  </li>
                )}
              </ul>
            </Panel>

            <Panel title="Top rules">
              <ul className="space-y-2">
                {overview.topRules.map(([rule, count]) => (
                  <li key={rule} className="flex items-center justify-between gap-3 text-sm">
                    <span className="truncate font-mono text-xs">{rule}</span>
                    <span className="tabular-nums text-muted-foreground">{count}</span>
                  </li>
                ))}
              </ul>
            </Panel>
          </div>
        </>
      )}
    </AppShell>
  );
}
