import { IconSparkles } from "@tabler/icons-react";
import {
  QueryClient,
  QueryClientContext,
  queryOptions,
  useQuery,
} from "@tanstack/react-query";
import { useContext, useEffect, useRef, useSyncExternalStore } from "react";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { tryClient } from "@/lib/client";
import {
  currentOrganizationId,
  onOrganizationChange,
} from "@/lib/organizations/current";
import { cn } from "@/lib/utils";

export type ConversationContextInfo = {
  used_tokens: number;
  context_limit: number;
  remaining_tokens: number;
  percent_used: number;
  auto_compact_threshold: number;
  compacted: boolean;
  estimated_prompt_tokens?: number;
  system_tokens?: number;
  history_tokens?: number;
  tools_tokens?: number;
  server_kv_tokens?: number | null;
  online?: boolean;
  is_processing?: boolean;
  model_alias?: string | null;
  compacted_before_tokens?: number | null;
  compacted_after_tokens?: number | null;
  dropped_turns?: number;
  updated_at_ms?: number;
};

export const contextKeys = {
  conversation: (
    orgId: string | undefined,
    conversationId: string | undefined,
  ) => ["conversation-context", orgId ?? "", conversationId ?? ""] as const,
};

function isFiniteNonNeg(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value) && value >= 0;
}

function parseContextInfo(raw: unknown): ConversationContextInfo | null {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    return null;
  }
  const obj = raw as Record<string, unknown>;
  if (
    !isFiniteNonNeg(obj.used_tokens) ||
    !isFiniteNonNeg(obj.context_limit) ||
    obj.context_limit <= 0
  ) {
    return null;
  }
  const limit = obj.context_limit;
  const used = obj.used_tokens;
  const remaining = isFiniteNonNeg(obj.remaining_tokens)
    ? obj.remaining_tokens
    : Math.max(0, limit - used);
  const percentUsed = isFiniteNonNeg(obj.percent_used)
    ? Math.min(100, obj.percent_used)
    : Math.min(100, Math.round((used / limit) * 1000) / 10);
  const threshold = isFiniteNonNeg(obj.auto_compact_threshold)
    ? obj.auto_compact_threshold
    : Math.floor(limit * 0.75);

  return {
    used_tokens: used,
    context_limit: limit,
    remaining_tokens: remaining,
    percent_used: percentUsed,
    auto_compact_threshold: threshold,
    compacted: Boolean(obj.compacted),
    estimated_prompt_tokens: isFiniteNonNeg(obj.estimated_prompt_tokens)
      ? obj.estimated_prompt_tokens
      : undefined,
    system_tokens: isFiniteNonNeg(obj.system_tokens)
      ? obj.system_tokens
      : undefined,
    history_tokens: isFiniteNonNeg(obj.history_tokens)
      ? obj.history_tokens
      : undefined,
    tools_tokens: isFiniteNonNeg(obj.tools_tokens)
      ? obj.tools_tokens
      : undefined,
    server_kv_tokens: isFiniteNonNeg(obj.server_kv_tokens)
      ? obj.server_kv_tokens
      : null,
    online: typeof obj.online === "boolean" ? obj.online : undefined,
    is_processing:
      typeof obj.is_processing === "boolean" ? obj.is_processing : undefined,
    model_alias:
      typeof obj.model_alias === "string" ? obj.model_alias : undefined,
    compacted_before_tokens: isFiniteNonNeg(obj.compacted_before_tokens)
      ? obj.compacted_before_tokens
      : null,
    compacted_after_tokens: isFiniteNonNeg(obj.compacted_after_tokens)
      ? obj.compacted_after_tokens
      : null,
    dropped_turns: isFiniteNonNeg(obj.dropped_turns)
      ? obj.dropped_turns
      : undefined,
    updated_at_ms: isFiniteNonNeg(obj.updated_at_ms)
      ? obj.updated_at_ms
      : undefined,
  };
}

/**
 * Fetches `/api/v2/organizations/:orgId/conversations/:conversationId/context`.
 * Tolerates 404, 5xx, and offline errors cleanly by returning `null`.
 */
export async function fetchConversationContext(
  orgId: string,
  conversationId: string,
  signal?: AbortSignal,
): Promise<ConversationContextInfo | null> {
  if (!orgId || !conversationId) {
    return null;
  }
  const url = `/api/v2/organizations/${encodeURIComponent(orgId)}/conversations/${encodeURIComponent(conversationId)}/context`;
  try {
    const response = await tryClient(url, { signal });
    if (!response.ok) {
      return null;
    }
    const body = (await response.json().catch(() => null)) as unknown;
    return parseContextInfo(body);
  } catch {
    return null;
  }
}

export function conversationContextQueryOptions({
  orgId,
  conversationId,
  enabled = true,
}: {
  orgId: string | undefined;
  conversationId: string | undefined;
  enabled?: boolean;
}) {
  return queryOptions({
    queryKey: contextKeys.conversation(orgId, conversationId),
    queryFn: ({ signal }) => {
      if (!orgId || !conversationId) {
        return Promise.resolve(null);
      }
      return fetchConversationContext(orgId, conversationId, signal);
    },
    enabled: Boolean(enabled && orgId && conversationId),
    retry: false,
    staleTime: 1_000,
  });
}

const fallbackQueryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: false,
    },
  },
});

export function useConversationContext({
  orgId,
  conversationId,
  active = false,
  enabled = true,
  refreshKey,
}: {
  orgId?: string;
  conversationId?: string;
  active?: boolean;
  enabled?: boolean;
  refreshKey?: string | number;
}) {
  const contextClient = useContext(QueryClientContext);
  const storeOrgId = useSyncExternalStore(
    onOrganizationChange,
    currentOrganizationId,
    currentOrganizationId,
  );
  const resolvedOrgId = orgId ?? storeOrgId;
  const isEnabled = Boolean(
    enabled && resolvedOrgId && conversationId && contextClient,
  );

  const query = useQuery(
    {
      ...conversationContextQueryOptions({
        orgId: resolvedOrgId,
        conversationId,
        enabled: isEnabled,
      }),
      refetchInterval: active ? 1_500 : 12_000,
    },
    contextClient ?? fallbackQueryClient,
  );

  const prevActiveRef = useRef(active);
  const prevRefreshKeyRef = useRef(refreshKey);

  useEffect(() => {
    const activeEnded = prevActiveRef.current && !active;
    const keyChanged = prevRefreshKeyRef.current !== refreshKey;
    prevActiveRef.current = active;
    prevRefreshKeyRef.current = refreshKey;
    if (
      !isEnabled ||
      !contextClient ||
      (!activeEnded && !keyChanged) ||
      !resolvedOrgId ||
      !conversationId
    ) {
      return;
    }
    void contextClient.invalidateQueries({
      queryKey: contextKeys.conversation(resolvedOrgId, conversationId),
    });
  }, [
    active,
    contextClient,
    conversationId,
    isEnabled,
    refreshKey,
    resolvedOrgId,
  ]);

  return query;
}

export function formatContextTokens(tokens: number): string {
  const rounded = Math.max(0, Math.round(tokens));
  if (rounded < 1_000) {
    return String(rounded);
  }
  if (rounded < 100_000) {
    const k = rounded / 1_000;
    const fixed = k.toFixed(1);
    return fixed.endsWith(".0") ? `${fixed.slice(0, -2)}k` : `${fixed}k`;
  }
  return `${Math.round(rounded / 1_000)}k`;
}

export type ContextMeterProps = {
  orgId?: string;
  conversationId?: string;
  active?: boolean;
  refreshKey?: string | number;
  context?: ConversationContextInfo | null;
  className?: string;
};

export function ContextMeter({
  orgId,
  conversationId,
  active = false,
  refreshKey,
  context,
  className,
}: ContextMeterProps) {
  const query = useConversationContext({
    orgId,
    conversationId,
    active,
    refreshKey,
    enabled: context === undefined && Boolean(conversationId),
  });

  const data = context !== undefined ? context : query.data;
  if (!data || data.context_limit <= 0) {
    return null;
  }

  const pctUsed = Math.max(
    0,
    Math.min(100, (data.used_tokens / data.context_limit) * 100),
  );
  const pctLeft = Math.max(0, Math.round(100 - pctUsed));

  const barTone =
    pctUsed >= 85
      ? "bg-rose-500"
      : pctUsed >= 65
        ? "bg-amber-500"
        : "bg-emerald-500";

  const pillTone =
    pctUsed >= 85
      ? "border-rose-500/35 bg-rose-500/5 text-foreground"
      : pctUsed >= 65
        ? "border-amber-500/35 bg-amber-500/5 text-foreground"
        : "border-border/70 bg-muted/40 text-muted-foreground";

  const usedShort = formatContextTokens(data.used_tokens);
  const limitShort = formatContextTokens(data.context_limit);
  const ariaLabel = `Context window ${usedShort} of ${limitShort} tokens used, ${pctLeft}% left${data.compacted ? ", compacted" : ""}`;

  return (
    <Tooltip>
      <TooltipTrigger
        render={
          <button
            aria-label={ariaLabel}
            className={cn(
              "inline-flex h-7 shrink-0 items-center gap-2 rounded-full border px-2.5 text-xs transition-colors hover:bg-muted/80 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
              pillTone,
              className,
            )}
            data-slot="context-meter"
            type="button"
          >
            <span
              aria-hidden
              className="h-1.5 w-9 overflow-hidden rounded-full bg-muted"
            >
              <span
                className={cn(
                  "block h-full rounded-full transition-[width,background-color] duration-300",
                  barTone,
                )}
                style={{ width: `${Math.max(pctUsed > 0 ? 4 : 0, pctUsed)}%` }}
              />
            </span>
            <span className="tabular-nums whitespace-nowrap">
              <span className="font-medium text-foreground">{usedShort}</span>
              <span className="text-muted-foreground"> / {limitShort} tok</span>
            </span>
            <span className="hidden tabular-nums whitespace-nowrap text-muted-foreground sm:inline">
              · {pctLeft}% left
            </span>
            {data.compacted ? (
              <span className="inline-flex items-center gap-0.5 rounded-full bg-amber-500/15 px-1.5 py-0.5 text-[10px] font-medium leading-none text-amber-600 dark:text-amber-400">
                <IconSparkles aria-hidden className="size-2.5" />
                Compacted
              </span>
            ) : null}
          </button>
        }
      />
      <TooltipContent
        arrowClassName="bg-[#141720] fill-[#141720]"
        className="w-64 flex-col items-stretch gap-1.5 rounded-lg border border-white/10 bg-[#141720] p-2.5 text-xs text-zinc-100 shadow-xl"
        side="top"
      >
        <div className="flex items-center justify-between gap-2 font-medium text-zinc-100">
          <span>Context window</span>
          <span className="tabular-nums">
            {Math.round(data.used_tokens).toLocaleString()} /{" "}
            {Math.round(data.context_limit).toLocaleString()} tok
          </span>
        </div>
        <div className="h-1.5 w-full overflow-hidden rounded-full bg-white/10">
          <div
            className={cn("h-full rounded-full", barTone)}
            style={{ width: `${Math.max(pctUsed > 0 ? 3 : 0, pctUsed)}%` }}
          />
        </div>
        <div className="flex items-center justify-between text-[11px] text-zinc-300 tabular-nums">
          <span>
            {Math.round(data.remaining_tokens).toLocaleString()} tok remaining
          </span>
          <span>{pctLeft}% left</span>
        </div>
        {(data.system_tokens !== undefined ||
          data.history_tokens !== undefined ||
          data.tools_tokens !== undefined) && (
          <div className="mt-0.5 space-y-0.5 border-t border-white/10 pt-1.5 text-[11px] text-zinc-300">
            {data.system_tokens !== undefined ? (
              <div className="flex justify-between tabular-nums">
                <span className="text-zinc-400">System</span>
                <span>
                  {Math.round(data.system_tokens).toLocaleString()} tok
                </span>
              </div>
            ) : null}
            {data.history_tokens !== undefined ? (
              <div className="flex justify-between tabular-nums">
                <span className="text-zinc-400">Messages</span>
                <span>
                  {Math.round(data.history_tokens).toLocaleString()} tok
                </span>
              </div>
            ) : null}
            {data.tools_tokens !== undefined && data.tools_tokens > 0 ? (
              <div className="flex justify-between tabular-nums">
                <span className="text-zinc-400">Tools schema</span>
                <span>
                  {Math.round(data.tools_tokens).toLocaleString()} tok
                </span>
              </div>
            ) : null}
            {data.server_kv_tokens !== null &&
            data.server_kv_tokens !== undefined ? (
              <div className="flex justify-between tabular-nums">
                <span className="text-zinc-400">Server KV slot</span>
                <span>
                  {Math.round(data.server_kv_tokens).toLocaleString()} tok
                </span>
              </div>
            ) : null}
            <div className="flex justify-between text-zinc-400 tabular-nums">
              <span>Auto-compact at</span>
              <span>
                {Math.round(data.auto_compact_threshold).toLocaleString()} tok
              </span>
            </div>
          </div>
        )}
        {data.compacted ? (
          <div className="mt-0.5 border-t border-white/10 pt-1.5 text-[11px] text-amber-300">
            Auto-compacted
            {data.compacted_before_tokens && data.compacted_after_tokens
              ? ` (${Math.round(data.compacted_before_tokens).toLocaleString()} → ${Math.round(data.compacted_after_tokens).toLocaleString()} tok)`
              : ""}
            {data.dropped_turns
              ? ` · summarized ${data.dropped_turns} older ${data.dropped_turns === 1 ? "turn" : "turns"}`
              : ""}
          </div>
        ) : null}
        {data.online === false ? (
          <div className="text-[11px] text-zinc-400">
            Model server offline · using fallback limit
          </div>
        ) : null}
      </TooltipContent>
    </Tooltip>
  );
}
