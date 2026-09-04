import { AlertTriangle, Database, Loader2 } from "lucide-react";
import { errorMessage } from "@/lib/adshield/api";
import { cn } from "@/lib/utils";

export function LoadingBlock({ label = "Loading backend data…" }: { label?: string }) {
  return (
    <div className="flex items-center justify-center gap-2 py-10 text-sm text-muted-foreground">
      <Loader2 className="size-4 animate-spin" /> {label}
    </div>
  );
}

export function ErrorBlock({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  return (
    <div className="rounded-md border border-destructive/40 bg-destructive/10 p-4">
      <p className="flex items-center gap-2 text-sm font-medium text-destructive">
        <AlertTriangle className="size-4" /> Backend request failed
      </p>
      <p className="mt-1 text-sm text-muted-foreground">{errorMessage(error)}</p>
      {onRetry && (
        <button
          onClick={onRetry}
          className="mt-3 rounded-md border border-border px-3 py-1.5 text-xs text-muted-foreground hover:text-foreground"
        >
          Retry
        </button>
      )}
    </div>
  );
}

/** Always visible when the screen is rendering fixtures instead of live data. */
export function DemoBadge({ className }: { className?: string }) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full border border-severity-medium/50 bg-severity-medium/10 px-2 py-0.5 font-mono text-[10px] uppercase tracking-widest text-severity-medium",
        className,
      )}
    >
      <Database className="size-3" /> Demo data / mock mode
    </span>
  );
}
