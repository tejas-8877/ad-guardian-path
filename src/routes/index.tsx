import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { ShieldCheck, Lock } from "lucide-react";
import { useAuth } from "@/lib/adshield/auth";
import { DOMAIN } from "@/lib/adshield/data";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "ADShield — Active Directory Attack-Path Analysis" },
      {
        name: "description",
        content:
          "Sign in with domain credentials to review Active Directory misconfigurations, Tier-0 attack paths and endpoint malware triage.",
      },
      { property: "og:title", content: "ADShield — AD Security Assessment Console" },
      {
        property: "og:description",
        content: "Attack-path analysis, misconfiguration findings and malware triage for corp.local.",
      },
    ],
  }),
  component: LoginPage,
});

const DEMO = [
  { user: "j.doe", role: "Standard User" },
  { user: "r.patel", role: "IT Support" },
  { user: "t.admin", role: "Security Admin" },
];

function LoginPage() {
  const { login, user, ready } = useAuth();
  const navigate = useNavigate();
  const [username, setUsername] = useState("t.admin");
  const [password, setPassword] = useState("Passw0rd!");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (ready && user) navigate({ to: "/dashboard", replace: true });
  }, [ready, user, navigate]);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const u = await login(username, password);
      navigate({ to: u.role === "standard_user" ? "/my-hygiene" : "/dashboard", replace: true });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Authentication failed.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="grid min-h-screen lg:grid-cols-2">
      <div className="hidden flex-col justify-between border-r border-border bg-sidebar p-10 lg:flex">
        <div className="flex items-center gap-2">
          <ShieldCheck className="size-6 text-primary" />
          <span className="text-lg font-semibold tracking-tight">ADShield</span>
        </div>
        <div>
          <h1 className="max-w-md text-3xl font-semibold leading-tight">
            Active Directory attack-path analysis for the modern SOC
          </h1>
          <p className="mt-4 max-w-md text-sm text-muted-foreground">
            Continuous LDAP collection, DACL-aware graph analysis, MITRE-mapped misconfiguration
            findings and static malware triage — all behind domain-group RBAC.
          </p>
          <dl className="mt-8 grid grid-cols-3 gap-4 font-mono text-xs uppercase tracking-widest text-muted-foreground">
            <div>
              <dt>Edges</dt>
              <dd className="mt-1 text-2xl font-semibold text-foreground">DACL</dd>
            </div>
            <div>
              <dt>Paths</dt>
              <dd className="mt-1 text-2xl font-semibold text-foreground">Tier-0</dd>
            </div>
            <div>
              <dt>Triage</dt>
              <dd className="mt-1 text-2xl font-semibold text-foreground">YARA</dd>
            </div>
          </dl>
        </div>
        <p className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
          Authorised use only · All sessions are logged
        </p>
      </div>

      <div className="flex items-center justify-center p-6">
        <form onSubmit={onSubmit} className="w-full max-w-sm">
          <div className="mb-8 flex items-center gap-2 lg:hidden">
            <ShieldCheck className="size-5 text-primary" />
            <span className="font-semibold tracking-tight">ADShield</span>
          </div>
          <h2 className="text-xl font-semibold">Domain sign-in</h2>
          <p className="mt-1 font-mono text-[11px] uppercase tracking-widest text-muted-foreground">
            {DOMAIN}
          </p>

          <label className="mt-6 block text-sm">
            <span className="text-muted-foreground">Username</span>
            <input
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoComplete="username"
              className="mt-1 w-full rounded-md border border-input bg-background px-3 py-2 font-mono text-sm outline-none focus:border-primary"
            />
          </label>
          <label className="mt-4 block text-sm">
            <span className="text-muted-foreground">Password</span>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
              className="mt-1 w-full rounded-md border border-input bg-background px-3 py-2 font-mono text-sm outline-none focus:border-primary"
            />
          </label>

          {error && (
            <p className="mt-4 rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-sm text-destructive">
              {error}
            </p>
          )}

          <button
            type="submit"
            disabled={busy}
            className="mt-6 flex w-full items-center justify-center gap-2 rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground transition-colors hover:bg-primary/90 disabled:opacity-60"
          >
            <Lock className="size-4" />
            {busy ? "Binding to directory…" : "Sign in"}
          </button>

          <div className="mt-8 rounded-md border border-border p-3">
            <p className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
              Demo accounts · Passw0rd!
            </p>
            <ul className="mt-2 space-y-1 text-xs">
              {DEMO.map((d) => (
                <li key={d.user} className="flex justify-between">
                  <button
                    type="button"
                    onClick={() => {
                      setUsername(d.user);
                      setPassword("Passw0rd!");
                    }}
                    className="font-mono text-primary hover:underline"
                  >
                    {d.user}
                  </button>
                  <span className="text-muted-foreground">{d.role}</span>
                </li>
              ))}
            </ul>
          </div>
        </form>
      </div>
    </div>
  );
}
