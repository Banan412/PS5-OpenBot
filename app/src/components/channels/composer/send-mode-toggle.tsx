import { IconBolt, IconClock } from "@tabler/icons-react";
import { type SendMode, useSendMode } from "@/lib/settings/send-mode";
import { cn } from "@/lib/utils";

type SendModeOption = {
  value: SendMode;
  label: string;
  tooltip: string;
  icon: typeof IconClock;
  activeClassName: string;
};

const SEND_MODE_OPTIONS: readonly SendModeOption[] = [
  {
    value: "queue",
    label: "Queue",
    tooltip: "Queue — Wait for the current turn to finish when busy",
    icon: IconClock,
    activeClassName:
      "bg-background text-foreground shadow-xs ring-1 ring-border/70",
  },
  {
    value: "instant",
    label: "Instant",
    tooltip: "Instant — Interrupt active or stuck turns and send immediately",
    icon: IconBolt,
    activeClassName:
      "bg-amber-500/15 text-amber-700 ring-1 ring-amber-500/35 dark:text-amber-300",
  },
];

export type SendModeToggleProps = {
  value?: SendMode;
  onChange?: (mode: SendMode) => void;
  disabled?: boolean;
  className?: string;
};

/**
 * Compact segmented toggle between `Queue` (wait when busy) and `Instant` (interrupt & send now).
 */
export function SendModeToggle({
  value,
  onChange,
  disabled = false,
  className,
}: SendModeToggleProps) {
  const [storedMode, setStoredMode] = useSendMode();
  const activeMode = value ?? storedMode;

  const handleSelect = (mode: SendMode) => {
    if (disabled || mode === activeMode) return;
    if (onChange) {
      onChange(mode);
      return;
    }
    setStoredMode(mode);
  };

  return (
    <fieldset
      aria-label="Send mode"
      className={cn(
        "m-0 inline-flex h-7 shrink-0 items-center gap-0.5 rounded-full border border-border/70 bg-muted/40 p-0.5 text-xs",
        className,
      )}
      data-send-mode={activeMode}
      data-slot="send-mode-toggle"
    >
      {SEND_MODE_OPTIONS.map((option) => {
        const Icon = option.icon;
        const selected = activeMode === option.value;
        return (
          <button
            aria-label={`Send mode: ${option.label}`}
            aria-pressed={selected}
            className={cn(
              "inline-flex h-6 items-center gap-1 rounded-full px-2 font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/50 disabled:pointer-events-none disabled:opacity-50",
              selected
                ? option.activeClassName
                : "text-muted-foreground hover:text-foreground",
            )}
            data-send-mode-option={option.value}
            disabled={disabled}
            key={option.value}
            onClick={() => handleSelect(option.value)}
            title={option.tooltip}
            type="button"
          >
            <Icon aria-hidden="true" className="size-3 shrink-0" />
            <span>{option.label}</span>
          </button>
        );
      })}
    </fieldset>
  );
}
