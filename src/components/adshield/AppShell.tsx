import { Link, useNavigate, useRouterState } from "@tanstack/react-router";
import type { ReactNode } from "react";
import { useEffect } from "react";
import {
  Activity,
  BugPlay,
  LayoutDashboard,
  LogOut,
  Network,
  ServerCog,
  ShieldAlert,
  ShieldCheck,
  Radar,
} from "lucide-react";
import { ROLE_LABEL, useAuth, useLive } from "@/lib/adshield/auth";
import { errorMessage } from "@/lib/adshield/api";
import { AD_CONNECTION, DOMAIN } from "@/lib/adshield/data";
import { useAdHealth, useCollectAd } from "@/lib/adshield/hooks";
import { cn } from "@/lib/utils";

const NAV = [
  { to: "/dashboard", label: "Overview", icon: LayoutDashboard, permission: "view:findings" },
  { to: "/attack-paths", label: "Attack Paths", icon: Network, permission: "view:attack_paths" },
  {
    to: "/compromise-impact",
    label: "Compromise Impact",
    icon: Radar,
    permission: "view:attack_paths",
  },
  { to: "/assets", label: "Assets", icon: ServerCog, permission: "view:assets" },
  { to: "/findings", label: "Findings", icon: ShieldAlert, permission: "view:findings" },
  { to: "/malware", label: "Malware Triage", icon: BugPlay, permission: "submit:malware_sample" },
  { to: "/my-hygiene", label: "My Hygiene", icon: Activity, permission: "view:own_hygiene" },
] as const;

export function AppShell({
  children,
  title,
  subtitle,
  requiredPermission,
}: {
  children: ReactNode;
  title: string;
  subtitle?: string;
  requiredPermission?: string;
}) {
  const { user, ready, logout, can } = useAuth();
  const navigate = useNavigate();
  const pathname = useRouterState({ select: (s) => s.location.pathname });
  const live = useLive();
  const health = useAdHealth();
  const collect = useCollectAd();

  useEffect(() => {
    if (ready && !user) navigate({ to: "/" });
  }, [ready, user, navigate]);

  if (!ready || !user) {
    return (
      <div className="flex min-h-screen items-center justify-center text-sm text-muted-foreground">
        Establishing secure session…
      </div>
    );
  }

  const denied = requiredPermission && !can(requiredPermission);

  return (
    <div className="flex min-h-screen">
      <aside className="hidden w-60 shrink-0 flex-col border-r border-border bg-sidebar md:flex">
        <div className="flex items-center gap-2 border-b border-sidebar-border px-5 py-4">
          <ShieldCheck className="size-5 text-primary" />
          <div>
            <p className="font-semibold tracking-tight">ADShield</p>
            <p className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
              {DOMAIN}
            </p>
          </div>
        </div>
        <div className="border-b border-sidebar-border px-5 py-3">
          <p className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
            Directory connection
          </p>
          {live ? (
            health.isPending ? (
              <p className="mt-1 text-xs text-muted-foreground">Checking directory…</p>
            ) : health.isError || !health.data ? (
              <p className="mt-1 flex items-center gap-2 text-xs text-severity-critical">
                <span className="size-2 rounded-full bg-severity-critical" />
                Backend unreachable
              </p>
            ) : (
              <>
                <p className="mt-1 flex items-center gap-2 text-xs">
                  <span
                    className={cn(
                      "size-2 rounded-full",
                      health.data.connected ? "bg-severity-low" : "bg-severity-critical",
                    )}
                  />
                  <span className="font-mono">
                    {health.data.connector.toUpperCase()} · {health.data.protocol}:{health.data.port}
                  </span>
                </p>
                <p className="mt-1 truncate font-mono text-[10px] text-muted-foreground">
                  {health.data.domain} · {health.data.server}
                  {health.data.latency_ms != null && ` · ${health.data.latency_ms} ms`}
                </p>
                {health.data.error && (
                  <p className="mt-1 font-mono text-[10px] text-severity-critical">
                    {health.data.error}
                  </p>
                )}
              </>
            )
          ) : (
            <>
              <p className="mt-1 flex items-center gap-2 text-xs">
                <span className="size-2 rounded-full bg-severity-medium" />
                <span className="font-mono">DEMO DATA · MOCK MODE</span>
              </p>
              <p className="mt-1 truncate font-mono text-[10px] text-muted-foreground">
                {AD_CONNECTION.server} (fixture)
              </p>
            </>
          )}
          {live && (
            <>
              <button
                onClick={() => collect.mutate()}
                disabled={collect.isPending}
                className="mt-3 w-full rounded-md border border-border px-2 py-1.5 font-mono text-[10px] uppercase tracking-widest text-muted-foreground transition-colors hover:border-primary hover:text-primary disabled:opacity-50"
              >
                {collect.isPending ? "Collecting…" : "Collect / refresh AD data"}
              </button>
              {collect.isError && (
                <p className="mt-1 font-mono text-[10px] text-severity-critical">
                  {errorMessage(collect.error)}
                </p>
              )}
              {collect.isSuccess && collect.data && (
                <p className="mt-1 font-mono text-[10px] text-severity-low">
                  {collect.data.users + collect.data.groups + collect.data.computers} objects ·{" "}
                  {collect.data.findings} findings · risk {collect.data.risk_score} ·{" "}
                  {collect.data.duration_ms} ms
                </p>
              )}
            </>
          )}
        </div>
        <nav className="flex-1 space-y-1 p-3">
          {NAV.filter((item) => can(item.permission)).map((item) => {
            const active = pathname === item.to;
            return (
              <Link
                key={item.to}
                to={item.to}
                className={cn(
                  "flex items-center gap-3 rounded-md px-3 py-2 text-sm transition-colors",
                  active
                    ? "bg-sidebar-accent text-primary"
                    : "text-muted-foreground hover:bg-sidebar-accent hover:text-foreground",
                )}
              >
                <item.icon className="size-4" />
                {item.label}
              </Link>
            );
          })}
        </nav>
        <div className="border-t border-sidebar-border p-3">
          <p className="truncate text-sm font-medium">{user.displayName}</p>
          <p className="font-mono text-[10px] uppercase tracking-widest text-primary">
            {ROLE_LABEL[user.role]}
          </p>
          <button
            onClick={() => {
              logout();
              navigate({ to: "/" });
            }}
            className="mt-3 flex w-full items-center justify-center gap-2 rounded-md border border-border px-3 py-2 text-xs text-muted-foreground transition-colors hover:border-destructive hover:text-destructive"
          >
            <LogOut className="size-3.5" /> Sign out
          </button>
        </div>
      </aside>

      <main className="min-w-0 flex-1">
        <header className="border-b border-border bg-surface/60 px-5 py-4 backdrop-blur md:px-8">
          <h1 className="text-lg font-semibold md:text-xl">{title}</h1>
          {subtitle && <p className="mt-1 text-sm text-muted-foreground">{subtitle}</p>}
          <nav className="mt-3 flex gap-2 overflow-x-auto md:hidden">
            {NAV.filter((item) => can(item.permission)).map((item) => (
              <Link
                key={item.to}
                to={item.to}
                className={cn(
                  "whitespace-nowrap rounded-full border px-3 py-1 text-xs",
                  pathname === item.to
                    ? "border-primary text-primary"
                    : "border-border text-muted-foreground",
                )}
              >
                {item.label}
              </Link>
            ))}
          </nav>
        </header>
        <div className="p-5 md:p-8">
          {denied ? (
            <div className="rounded-lg border border-destructive/40 bg-destructive/10 p-6">
              <p className="font-medium text-destructive">Access denied</p>
              <p className="mt-1 text-sm text-muted-foreground">
                Your role ({ROLE_LABEL[user.role]}) lacks the{" "}
                <code className="font-mono">{requiredPermission}</code> permission. Contact the SOC
                team if you believe this is an error.
              </p>
            </div>
          ) : (
            children
          )}
        </div>
      </main>
    </div>
  );
}
