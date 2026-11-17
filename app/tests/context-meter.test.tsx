import { afterAll, afterEach, beforeAll, expect, test } from "bun:test";
import { GlobalRegistrator } from "@happy-dom/global-registrator";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, waitFor } from "@testing-library/react";
import {
  ContextMeter,
  type ConversationContextInfo,
  fetchConversationContext,
  formatContextTokens,
} from "@/components/chat/context-meter";
import { TooltipProvider } from "@/components/ui/tooltip";
import { setCurrentOrganization } from "@/lib/organizations/current";

const originalFetch = globalThis.fetch;

beforeAll(() => {
  GlobalRegistrator.register({ url: "http://localhost/" });
});

afterEach(() => {
  cleanup();
  setCurrentOrganization(undefined);
  globalThis.fetch = originalFetch;
});

afterAll(() => {
  GlobalRegistrator.unregister();
});

test("formatContextTokens formats compact llama.cpp-style counts", () => {
  expect(formatContextTokens(842)).toBe("842");
  expect(formatContextTokens(4200)).toBe("4.2k");
  expect(formatContextTokens(8000)).toBe("8k");
  expect(formatContextTokens(16384)).toBe("16.4k");
});

test("fetchConversationContext tolerates 404 and offline errors cleanly", async () => {
  globalThis.fetch = Object.assign(
    async () => new Response("not found", { status: 404 }),
    { preconnect: originalFetch.preconnect },
  );
  expect(await fetchConversationContext("default", "conv-1")).toBeNull();

  globalThis.fetch = Object.assign(
    async () => {
      throw new Error("network down");
    },
    { preconnect: originalFetch.preconnect },
  );
  expect(await fetchConversationContext("default", "conv-1")).toBeNull();
});

test("ContextMeter renders used/limit tokens, % left, and Compacted badge", () => {
  const snapshot: ConversationContextInfo = {
    used_tokens: 4200,
    context_limit: 8192,
    remaining_tokens: 3992,
    percent_used: 51.3,
    auto_compact_threshold: 6144,
    compacted: true,
    system_tokens: 500,
    history_tokens: 3100,
    tools_tokens: 600,
    compacted_before_tokens: 7100,
    compacted_after_tokens: 4200,
    dropped_turns: 3,
  };

  const view = render(
    <TooltipProvider>
      <ContextMeter context={snapshot} />
    </TooltipProvider>,
  );

  const meter = view.container.querySelector('[data-slot="context-meter"]');
  expect(meter).not.toBeNull();
  expect(meter?.textContent).toContain("4.2k");
  expect(meter?.textContent).toContain("8.2k tok");
  expect(meter?.textContent).toContain("49% left");
  expect(meter?.textContent).toContain("Compacted");
});

test("ContextMeter fetches live context endpoint and hides cleanly on 404", async () => {
  setCurrentOrganization("default");
  globalThis.fetch = Object.assign(
    async () =>
      Response.json({
        used_tokens: 1500,
        context_limit: 16384,
        remaining_tokens: 14884,
        percent_used: 9.2,
        auto_compact_threshold: 12288,
        compacted: false,
      }),
    { preconnect: originalFetch.preconnect },
  );

  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  const view = render(
    <QueryClientProvider client={qc}>
      <TooltipProvider>
        <ContextMeter conversationId="conv-live" />
      </TooltipProvider>
    </QueryClientProvider>,
  );

  await waitFor(() => {
    const el = view.container.querySelector('[data-slot="context-meter"]');
    expect(el).not.toBeNull();
    expect(el?.textContent).toContain("1.5k");
    expect(el?.textContent).toContain("16.4k tok");
    expect(el?.textContent).toContain("91% left");
    expect(el?.textContent).not.toContain("Compacted");
  });
});

test("ContextMeter hover tooltip uses dark surface styling instead of white bg-foreground", async () => {
  const snapshot: ConversationContextInfo = {
    used_tokens: 4200,
    context_limit: 8192,
    remaining_tokens: 3992,
    percent_used: 51.3,
    auto_compact_threshold: 6144,
    compacted: true,
    system_tokens: 500,
    history_tokens: 3100,
    tools_tokens: 600,
    compacted_before_tokens: 7100,
    compacted_after_tokens: 4200,
    dropped_turns: 2,
  };

  const view = render(
    <TooltipProvider delay={0}>
      <ContextMeter context={snapshot} />
    </TooltipProvider>,
  );

  const trigger = view.container.querySelector(
    '[data-slot="context-meter"]',
  ) as HTMLElement;
  expect(trigger).not.toBeNull();
  fireEvent.pointerEnter(trigger);
  fireEvent.focus(trigger);

  await waitFor(() => {
    const popup = document.querySelector(
      '[data-slot="tooltip-content"]',
    ) as HTMLElement | null;
    expect(popup).not.toBeNull();
    expect(popup?.className).toContain("bg-[#141720]");
    expect(popup?.className).toContain("border-white/10");
    expect(popup?.className).toContain("text-zinc-100");
    const arrow = popup?.querySelector(
      '[data-slot="tooltip-arrow"]',
    ) as HTMLElement | null;
    expect(arrow).not.toBeNull();
    expect(arrow?.className).toContain("bg-[#141720]");
    expect(arrow?.className).toContain("fill-[#141720]");
    expect(popup?.innerHTML).toContain("bg-white/10");
    expect(popup?.innerHTML).toContain("border-white/10");
    expect(popup?.innerHTML).not.toContain("bg-background/20");
    expect(popup?.innerHTML).not.toContain("border-background/15");
  });
});
