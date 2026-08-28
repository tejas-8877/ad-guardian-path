import { createFileRoute } from "@tanstack/react-router";
import { AppShell } from "@/components/adshield/AppShell";
import { Panel, SeverityBadge, StatTile } from "@/components/adshield/ui-bits";
import { useAuth, ROLE_LABEL } from "@/lib/adshield/auth";
import { FINDINGS, PRINCIPALS } from "@/lib/adshield/data";

export const Route = createFileRoute("/my-hygiene")({
  head: () => ({
    meta: [
      { title: "My Account Hygiene — ADShield" },
      {
        name: "description",
        content: "Personal Active Directory account hygiene: password age, SPNs and open findings.",
      },
      { property: "og:title", content: "My Account Hygiene — ADShield" },
      { property: "og:description", content: "Your own AD account security posture and fixes." },
    ],
  }),
  component: HygienePage,
});

function HygienePage() {
  const { user } = useAuth();
  const principal = PRINCIPALS.find((p) => p.objectSid === user?.objectSid);
  const mine = FINDINGS.filter((f) => f.principalSid === user?.objectSid);

  return (
    <AppShell
      title="My Account Hygiene"
      subtitle="Findings scoped strictly to your own directory object"
      requiredPermission="view:own_hygiene"
    >
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatTile label="Account" value={user?.samAccountName ?? "—"} hint={ROLE_LABEL[user!.role]} />
        <StatTile
          label="Password age"
          value={principal?.passwordAgeDays ?? "—"}
          hint="days since last set"
          tone={(principal?.passwordAgeDays ?? 0) > 365 ? "critical" : "default"}
        />
        <StatTile label="SPNs registered" value={principal?.spns.length ?? 0} hint="Kerberoasting surface" />
        <StatTile
          label="Open findings"
          value={mine.length}
          tone={mine.length ? "critical" : "default"}
        />
      </div>

      <Panel title="Your findings" className="mt-4">
        {mine.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            No hygiene issues detected on your account. Keep MFA enrolled and report phishing to the
            SOC.
          </p>
        ) : (
          <ul className="space-y-2">
            {mine.map((f) => (
              <li key={f.id} className="rounded-md border border-border p-3">
                <div className="flex flex-wrap items-center gap-2">
                  <SeverityBadge severity={f.severity} />
                  <span className="text-sm font-medium">{f.title}</span>
                  <span className="ml-auto font-mono text-[10px] uppercase tracking-widest text-primary">
                    {f.mitre}
                  </span>
                </div>
                <p className="mt-2 text-sm text-muted-foreground">{f.description}</p>
                <p className="mt-2 text-sm">
                  <span className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
                    Fix ·{" "}
                  </span>
                  {f.remediation}
                </p>
              </li>
            ))}
          </ul>
        )}
      </Panel>
    </AppShell>
  );
}
