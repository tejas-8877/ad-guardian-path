import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import { AppShell } from "@/components/adshield/AppShell";
import { DemoBadge, ErrorBlock, LoadingBlock } from "@/components/adshield/states";
import { Panel } from "@/components/adshield/ui-bits";
import { useLive } from "@/lib/adshield/auth";
import { PRINCIPALS } from "@/lib/adshield/data";
import type { Principal, PrincipalType } from "@/lib/adshield/data";
import { useAssets } from "@/lib/adshield/hooks";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/assets")({
  head: () => ({
    meta: [
      { title: "Directory Assets — ADShield" },
      {
        name: "description",
        content: "Inventory of users, groups, computers and GPOs collected from Active Directory.",
      },
      { property: "og:title", content: "Directory Assets — ADShield" },
      { property: "og:description", content: "Searchable AD object inventory with risk attributes." },
    ],
  }),
  component: AssetsPage,
});

const TYPES: (PrincipalType | "all")[] = ["all", "user", "group", "computer", "gpo"];

function AssetsPage() {
  const [type, setType] = useState<PrincipalType | "all">("all");
  const [q, setQ] = useState("");
  const [selected, setSelected] = useState<Principal | null>(null);

  const live = useLive();
  const query = useAssets(type);

  const source = live ? (query.data ?? []) : PRINCIPALS;
  const items = source.filter(
    (p) =>
      (type === "all" || p.type === type) &&
      (q === "" ||
        `${p.samAccountName} ${p.displayName}`.toLowerCase().includes(q.toLowerCase())),
  );

  return (
    <AppShell
      title="Directory Assets"
      subtitle={
        live
          ? "Objects from the latest backend collection with their security-relevant attributes"
          : "Fixture inventory — the backend is not connected"
      }
      requiredPermission="view:assets"
    >
      {!live && <DemoBadge className="mb-4" />}
      {live && query.isPending && <LoadingBlock label="Loading directory objects…" />}
      {live && query.isError && (
        <ErrorBlock error={query.error} onRetry={() => void query.refetch()} />
      )}
      {(!live || query.isSuccess) && (
      <div className="grid gap-4 lg:grid-cols-3">
        <Panel
          className="lg:col-span-2"
          title={`${items.length} objects`}
          action={
            <input
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="Search sAMAccountName…"
              className="w-48 rounded-md border border-input bg-background px-2 py-1 text-xs outline-none focus:border-primary"
            />
          }
        >
          <div className="mb-4 flex flex-wrap gap-2">
            {TYPES.map((t) => (
              <button
                key={t}
                onClick={() => setType(t)}
                className={cn(
                  "rounded-full border px-3 py-1 font-mono text-[10px] uppercase tracking-widest",
                  type === t
                    ? "border-primary text-primary"
                    : "border-border text-muted-foreground hover:text-foreground",
                )}
              >
                {t}
              </button>
            ))}
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
                  <th className="pb-2">Name</th>
                  <th className="pb-2">Type</th>
                  <th className="pb-2">State</th>
                  <th className="pb-2">Pwd age</th>
                </tr>
              </thead>
              <tbody>
                {items.map((p) => (
                  <tr
                    key={p.objectSid}
                    onClick={() => setSelected(p)}
                    className="cursor-pointer border-t border-border hover:bg-sidebar-accent"
                  >
                    <td className="py-2">
                      <span className="font-mono">{p.samAccountName}</span>
                      <span className="ml-2 text-xs text-muted-foreground">{p.displayName}</span>
                    </td>
                    <td className="py-2 font-mono text-xs text-muted-foreground">{p.type}</td>
                    <td className="py-2 text-xs">
                      {p.enabled ? (
                        <span className="text-severity-low">enabled</span>
                      ) : (
                        <span className="text-muted-foreground">disabled</span>
                      )}
                      {p.adminCount && <span className="ml-2 text-severity-critical">adminCount</span>}
                    </td>
                    <td className="py-2 font-mono text-xs tabular-nums text-muted-foreground">
                      {p.passwordAgeDays ?? "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>

        <Panel title="Object detail">
          {selected ? (
            <dl className="space-y-3 text-sm">
              <Row label="sAMAccountName" value={selected.samAccountName} mono />
              <Row label="Display name" value={selected.displayName} />
              <Row label="objectSid" value={selected.objectSid} mono />
              <Row label="Type" value={selected.type} mono />
              <Row label="Enabled" value={String(selected.enabled)} mono />
              <Row label="adminCount" value={String(selected.adminCount)} mono />
              <Row label="Domain controller" value={String(selected.domainController)} mono />
              <Row label="SPNs" value={selected.spns.length ? selected.spns.join(", ") : "none"} mono />
              <Row label="Password age (days)" value={String(selected.passwordAgeDays ?? "—")} mono />
              <Row label="Last logon (days)" value={String(selected.lastLogonDays ?? "—")} mono />
              {selected.os && <Row label="Operating system" value={selected.os} />}
              {selected.description && <Row label="Description" value={selected.description} />}
            </dl>
          ) : (
            <p className="text-sm text-muted-foreground">Select an object to inspect attributes.</p>
          )}
        </Panel>
      </div>
    </AppShell>
  );
}

function Row({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div>
      <dt className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
        {label}
      </dt>
      <dd className={cn("mt-0.5 break-words", mono && "font-mono text-xs")}>{value}</dd>
    </div>
  );
}
