import { IconBolt, IconHandStop, IconSparkles } from "@tabler/icons-react";
import {
  QueryClient,
  QueryClientContext,
  useMutation,
  useQuery,
} from "@tanstack/react-query";
import { useContext, useSyncExternalStore } from "react";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import {
  approvalSettingsQueryOptions,
  type ExecutionMode,
  normalizeExecutionMode,
  teamApprovalSettingsMutationOptions,
} from "@/lib/approvals";
import {
  currentOrganizationId,
  onOrganizationChange,
} from "@/lib/organizations/current";
import { cn } from "@/lib/utils";

export type ExecutionModeOption = {
  value: ExecutionMode;
  label: string;
  description: string;
  tooltip: string;
  icon: typeof IconHandStop;
  activeClassName: string;
};

export const EXECUTION_MODE_OPTIONS: readonly ExecutionModeOption[] = [
  {
    value: "ask",
    label: "Ask",
    description: "Confirm actions before running tools or commands.",
    tooltip: "Ask — Confirm actions before they run",
    icon: IconHandStop,
    activeClassName:
      "bg-background text-foreground shadow-xs ring-1 ring-border/70",
  },
  {
    value: "auto",
    label: "Auto",
    description: "Auto-run safe reads & web fetch; ask on writes.",
    tooltip: "Auto — Auto-run safe reads & web; ask on writes",
    icon: IconSparkles,
    activeClassName:
      "bg-sky-500/15 text-sky-700 ring-1 ring-sky-500/35 dark:text-sky-300",
  },
  {
    value: "turbo",
    label: "Turbo",
    description: "Auto-run all tools & commands without asking.",
    tooltip: "Turbo — Auto-run all tools & commands",
    icon: IconBolt,
    activeClassName:
      "bg-amber-500/15 text-amber-700 ring-1 ring-amber-500/35 dark:text-amber-300",
  },
];

const fallbackQueryClient = new QueryClient({
  defaultOptions: {
    queries: { retry: false },
  },
});

export type ExecutionModeSelectorProps = {
  orgId?: string;
  value?: ExecutionMode;
  onChange?: (mode: ExecutionMode) => void;
  disabled?: boolean;
  readOnly?: boolean;
  className?: string;
};

/**
 * Compact segmented selector for organization execution mode (`Ask` | `Auto` | `Turbo`).
 * Backed by `GET / PATCH /api/v2/organizations/{org}/approval-settings` (`executionMode`).
 */
export function ExecutionModeSelector({
  orgId,
  value,
  onChange,
  disabled = false,
  readOnly = false,
  className,
}: ExecutionModeSelectorProps) {
  const contextClient = useContext(QueryClientContext);
  const storeOrgId = useSyncExternalStore(
    onOrganizationChange,
    currentOrganizationId,
    currentOrganizationId,
  );
  const resolvedOrgId = orgId ?? storeOrgId;
  const controlled = value !== undefined;
  const queryEnabled = Boolean(!controlled && contextClient && resolvedOrgId);

  const settingsQuery = useQuery(
    approvalSettingsQueryOptions(resolvedOrgId, queryEnabled),
    contextClient ?? fallbackQueryClient,
  );

  const mutation = useMutation(
    teamApprovalSettingsMutationOptions(contextClient ?? fallbackQueryClient),
    contextClient ?? fallbackQueryClient,
  );

  const activeMode: ExecutionMode = controlled
    ? value
    : normalizeExecutionMode(
        mutation.isPending
          ? (mutation.variables?.executionMode ??
              settingsQuery.data?.executionMode)
          : settingsQuery.data?.executionMode,
      );

  const isDisabled = disabled || readOnly || mutation.isPending;

  const handleSelect = (mode: ExecutionMode) => {
    if (isDisabled || mode === activeMode) return;
    if (onChange) {
      onChange(mode);
      return;
    }
    if (!contextClient) return;
    mutation.mutate({ executionMode: mode });
  };

  return (
    <fieldset
      aria-label="Execution mode"
      className={cn(
        "m-0 inline-flex h-7 shrink-0 items-center gap-0.5 rounded-full border border-border/70 bg-muted/40 p-0.5 text-xs",
        className,
      )}
      data-execution-mode={activeMode}
      data-slot="execution-mode-selector"
      title={mutation.error ? mutation.error.message : undefined}
    >
      {EXECUTION_MODE_OPTIONS.map((option) => {
        const Icon = option.icon;
        const selected = activeMode === option.value;
        const tooltipText = readOnly
          ? `${option.tooltip} (Admins only)`
          : option.tooltip;
        return (
          <Tooltip key={option.value}>
            <TooltipTrigger
              render={
                <button
                  aria-label={option.label}
                  aria-pressed={selected}
                  className={cn(
                    "inline-flex h-6 items-center gap-1 rounded-full px-2 text-[11px] leading-none transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50",
                    selected
                      ? cn("font-medium", option.activeClassName)
                      : "text-muted-foreground hover:bg-muted/80 hover:text-foreground",
                  )}
                  data-mode={option.value}
                  disabled={isDisabled}
                  onClick={() => handleSelect(option.value)}
                  type="button"
                >
                  <Icon aria-hidden className="size-3 shrink-0" />
                  <span>{option.label}</span>
                </button>
              }
            />
            <TooltipContent
              arrowClassName="bg-[#141720] fill-[#141720]"
              className="border border-white/10 bg-[#141720] text-zinc-100 shadow-lg"
              side="top"
            >
              {tooltipText}
            </TooltipContent>
          </Tooltip>
        );
      })}
    </fieldset>
  );
}
