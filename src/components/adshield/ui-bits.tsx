import type { ReactNode } from "react";
import type { Severity } from "@/lib/adshield/data";
import { cn } from "@/lib/utils";

const SEVERITY_STYLE: Record<Severity, string> = {
  critical: "border-severity-critical/50 bg-severity-critical/15 text-severity-critical",
  high: "border-severity-high/50 bg-severity-high/15 text-severity-high",
  medium: "border-severity-medium/50 bg-severity-medium/15 text-severity-medium",
  low: "border-severity-low/50 bg-severity-low/15 text-severity-low",
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full border px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider",
        SEVERITY_STYLE[severity],
      )}
    >
      {severity}
    </span>
  );
}

export function Panel({
  title,
  action,
  children,
  className,
}: {
  title?: string;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section
      className={cn("rounded-lg border border-border bg-card/80 backdrop-blur-sm", className)}
    >
      {title && (
        <header className="flex items-center justify-between border-b border-border px-4 py-3">
          <h2 className="font-mono text-xs uppercase tracking-widest text-muted-foreground">
            {title}
          </h2>
          {action}
        </header>
      )}
      <div className="p-4">{children}</div>
    </section>
  );
}

export function StatTile({
  label,
  value,
  hint,
  tone = "default",
}: {
  label: string;
  value: string | number;
  hint?: string;
  tone?: "default" | "critical" | "primary";
}) {
  return (
    <div className="rounded-lg border border-border bg-card/80 p-4">
      <p className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
        {label}
      </p>
      <p
        className={cn(
          "mt-2 text-3xl font-semibold tabular-nums",
          tone === "critical" && "text-severity-critical",
          tone === "primary" && "text-primary",
        )}
      >
        {value}
      </p>
      {hint && <p className="mt-1 text-xs text-muted-foreground">{hint}</p>}
    </div>
  );
}
