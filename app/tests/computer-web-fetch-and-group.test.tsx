import {
  afterAll,
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  spyOn,
  test,
} from "bun:test";
import { EventType, type Message } from "@ag-ui/core";
import * as ReactCoreV2 from "@copilotkit/react-core/v2";
import { GlobalRegistrator } from "@happy-dom/global-registrator";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  act,
  cleanup,
  fireEvent,
  render,
  waitFor,
  within,
} from "@testing-library/react";
import type { ReactElement } from "react";
import {
  browserStepDetails,
  isBrowserStep,
} from "@/components/channels/browser-activity";
import { GroupChat } from "@/components/channels/group-chat";
import { ActivityLog } from "@/components/computer/activity-log";
import { ComputerView } from "@/components/computer/computer-view";
import { useAutoWatchScreen } from "@/components/computer/use-auto-watch-screen";
import {
  activityFor,
  clearActivity,
  conversationActivity,
  useConversationActivity,
} from "@/lib/computers/activity";
import { ComputerTools } from "@/lib/copilot/computer-tools";
import { findPendingTool } from "@/lib/copilot/handoff-resume";
import {
  latestGroupApprovalBot,
  selectGroupComputerBot,
} from "@/routes/_authed/_app/group/$channelId";
import { ME_PATH, meResponse } from "./accounts-api";
import { approvalInboxResponse, approvalWriteResponse } from "./approvals-api";
import { answerBotsList } from "./bots-api";
import { answerGroupRead } from "./conversations-api";
import { settleReactWork } from "./settle-react-work";

type Registered = Parameters<typeof ReactCoreV2.useFrontendTool>[0];

let originalFetch: typeof fetch;
let originalWebSocket: typeof WebSocket;
let originalIntersectionObserver: typeof IntersectionObserver | undefined;
let originalDecode: typeof HTMLImageElement.prototype.decode;

class QuietSocket {
  static readonly OPEN = 1;
  static readonly CLOSED = 3;
  readyState = QuietSocket.OPEN;
  onopen: (() => void) | null = null;
  onmessage: ((event: { data: string }) => void) | null = null;
  onerror: (() => void) | null = null;
  onclose: (() => void) | null = null;
  constructor(_url: string) {
    queueMicrotask(() => this.onopen?.());
  }
  send() {}
  close() {
    this.readyState = QuietSocket.CLOSED;
  }
}

beforeAll(() => {
  GlobalRegistrator.register({ url: "http://localhost/" });
  originalFetch = globalThis.fetch;
  originalWebSocket = globalThis.WebSocket;
  originalIntersectionObserver = globalThis.IntersectionObserver;
  originalDecode = HTMLImageElement.prototype.decode;
  globalThis.WebSocket = QuietSocket as unknown as typeof WebSocket;
  Reflect.deleteProperty(globalThis, "IntersectionObserver");
  HTMLImageElement.prototype.decode = () => Promise.resolve();
});

afterEach(() => {
  cleanup();
  globalThis.fetch = originalFetch;
});

afterAll(async () => {
  await settleReactWork();
  globalThis.fetch = originalFetch;
  globalThis.WebSocket = originalWebSocket;
  if (originalIntersectionObserver) {
    globalThis.IntersectionObserver = originalIntersectionObserver;
  }
  HTMLImageElement.prototype.decode = originalDecode;
  GlobalRegistrator.unregister();
});

function withQueries(ui: ReactElement) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>{ui}</QueryClientProvider>,
  );
}

describe("computer_web_fetch parity with computer_navigate", () => {
  test("computer-tools registers computer_web_fetch with NavigationStep and handles success, error, and denial", async () => {
    const registered: Registered[] = [];
    const copilotSpy = spyOn(ReactCoreV2, "useCopilotKit").mockImplementation(
      () => ({ copilotkit: { stopAgent: () => undefined } }) as never,
    );
    const toolSpy = spyOn(ReactCoreV2, "useFrontendTool").mockImplementation(
      (tool) => {
        if (!registered.some((entry) => entry.name === tool.name)) {
          registered.push(tool as unknown as Registered);
        }
      },
    );
    globalThis.fetch = (async (input: Parameters<typeof fetch>[0]) => {
      const path = String(input);
      const approvals = approvalInboxResponse(path, { requests: [] });
      if (approvals) return approvals;
      if (path.includes("/page-frame/")) return Response.json({ frame: null });
      if (path.endsWith("/control"))
        return Response.json({ holder: "bot", requested: false });
      if (path.endsWith("/status"))
        return Response.json({ botId: "default", state: "ready" });
      if (path.endsWith("/screenshot"))
        return Response.json({
          base64: "AAAA",
          width: 320,
          height: 200,
          capturedAt: new Date(0).toISOString(),
          url: "https://example.com/",
        });
      return new Response("not found", { status: 404 });
    }) as typeof fetch;

    try {
      withQueries(<ComputerTools />);
      cleanup();
      const tool = registered.find(
        (entry) => entry.name === "computer_web_fetch",
      );
      expect(tool).toBeDefined();
      const draw = tool!.render as unknown as (
        props: Record<string, unknown>,
      ) => ReactElement;

      const okView = withQueries(
        draw({
          name: "computer_web_fetch",
          toolCallId: "wf-ok",
          args: { url: "https://example.com/" },
          status: "complete",
          result: JSON.stringify({
            ok: true,
            url: "https://example.com/",
            title: "Example Domain",
            text: "Example Domain",
          }),
        }),
      );
      expect(
        okView.getByRole("button", { name: "Open the Bot's screen full size" }),
      ).toBeTruthy();
      expect(await okView.findByText("Example Domain")).toBeTruthy();
      cleanup();

      const errView = withQueries(
        draw({
          name: "computer_web_fetch",
          toolCallId: "wf-err",
          args: { url: "https://www.youtube.com/" },
          status: "complete",
          result: JSON.stringify({
            error: "resolved IP address is forbidden by SSRF policy",
          }),
        }),
      );
      expect(await errView.findByText("Opened, didn't work")).toBeTruthy();
      expect(errView.getByText("youtube.com")).toBeTruthy();
      expect(errView.container.querySelector("figure")).toBeNull();
      cleanup();

      const deniedView = withQueries(
        draw({
          name: "computer_web_fetch",
          toolCallId: "wf-denied",
          args: { url: "https://www.youtube.com/" },
          status: "complete",
          result: JSON.stringify({
            denied: true,
            reason: "The user denied permission for this action.",
          }),
        }),
      );
      expect(await deniedView.findByText("Blocked: Open")).toBeTruthy();
      expect(deniedView.getByText("youtube.com")).toBeTruthy();
      expect(deniedView.container.querySelector("figure")).toBeNull();
    } finally {
      copilotSpy.mockRestore();
      toolSpy.mockRestore();
    }
  });

  test("activity, activity-log, browser-activity, and handoff-resume handle computer_web_fetch", () => {
    const messages: Message[] = [
      {
        id: "a-1",
        role: "assistant",
        toolCalls: [
          {
            id: "wf-1",
            type: "function",
            function: {
              name: "computer_web_fetch",
              arguments: '{"url":"https://example.com"}',
            },
          },
        ],
      },
      {
        id: "t-1",
        role: "tool",
        toolCallId: "wf-1",
        content: JSON.stringify({
          ok: true,
          url: "https://example.com/",
          title: "Example Page",
        }),
      },
    ];

    const calls = conversationActivity(messages);
    expect(calls).toEqual([
      {
        id: "wf-1",
        did: {
          kind: "browser",
          step: "computer_web_fetch",
          subject: "https://example.com/",
          output: "Example Page",
        },
      },
    ]);

    const item = {
      kind: "tool" as const,
      id: "wf-1",
      toolCall: {
        id: "wf-1",
        type: "function" as const,
        function: {
          name: "computer_web_fetch",
          arguments: '{"url":"https://example.com"}',
        },
      },
      result: JSON.stringify({
        ok: true,
        url: "https://example.com/",
        title: "Example Page",
      }),
    };
    expect(isBrowserStep(item)).toBe(true);
    expect(browserStepDetails(item)).toMatchObject({
      label: "Opened page",
      href: "https://example.com/",
      title: "Example Page",
      failed: false,
      visited: true,
    });

    const failedDetails = browserStepDetails({
      ...item,
      result: JSON.stringify({ error: "SSRF blocked" }),
    });
    expect(failedDetails.failed).toBe(true);
    expect(failedDetails.reason).toBe("SSRF blocked");
    expect(failedDetails.visited).toBe(false);

    const pending = findPendingTool([messages[0]!], {
      requestId: "req-1",
      toolCallId: "wf-1",
    });
    expect(pending?.id).toBe("wf-1");
  });

  test("useConversationActivity auto-opens ?watch=true on live computer_web_fetch and ignores replays", () => {
    const coreSubscribers: Array<Record<string, (e: never) => void>> = [];
    const agentEventHandlers: Array<(e: { event: unknown }) => void> = [];
    const copilotSpy = spyOn(ReactCoreV2, "useCopilotKit").mockImplementation(
      () =>
        ({
          copilotkit: {
            subscribe: (sub: Record<string, (e: never) => void>) => {
              coreSubscribers.push(sub);
              return { unsubscribe: () => {} };
            },
          },
        }) as never,
    );
    globalThis.fetch = (async (input: Parameters<typeof fetch>[0]) => {
      const approvals = approvalInboxResponse(String(input), { requests: [] });
      if (approvals) return approvals;
      return Response.json({});
    }) as typeof fetch;

    const opened: number[] = [];
    const closed: number[] = [];
    function Harness({ messages }: { messages: Message[] }) {
      useConversationActivity("wf-bot", messages);
      useAutoWatchScreen({
        botId: "wf-bot",
        watching: false,
        busy: false,
        open: () => opened.push(1),
        close: () => closed.push(1),
      });
      return <ActivityLog computerId="wf-bot" />;
    }

    try {
      clearActivity("wf-bot");
      const view = withQueries(<Harness messages={[]} />);

      const mockAgent = {
        agentId: "wf-bot",
        subscribe: (sub: { onEvent: (e: { event: unknown }) => void }) => {
          agentEventHandlers.push(sub.onEvent);
          return { unsubscribe: () => {} };
        },
      };
      act(() => {
        for (const sub of coreSubscribers) {
          sub.onAgentRunStarted?.({ agent: mockAgent } as never);
        }
      });

      // Replay run with input must NOT auto-open ?watch=true
      act(() => {
        for (const onEvent of agentEventHandlers) {
          onEvent({
            event: { type: EventType.RUN_STARTED, input: { messages: [] } },
          });
          onEvent({
            event: {
              type: EventType.TOOL_CALL_START,
              toolCallId: "old-wf",
              toolCallName: "computer_web_fetch",
            },
          });
        }
      });
      expect(opened).toHaveLength(0);

      // Live run (RUN_STARTED without input) DOES auto-open ?watch=true
      act(() => {
        for (const onEvent of agentEventHandlers) {
          onEvent({ event: { type: EventType.RUN_STARTED } });
          onEvent({
            event: {
              type: EventType.TOOL_CALL_START,
              toolCallId: "live-wf",
              toolCallName: "computer_web_fetch",
            },
          });
        }
      });
      expect(opened).toHaveLength(1);

      // Denied result withdraws the announcement
      act(() => {
        for (const onEvent of agentEventHandlers) {
          onEvent({
            event: {
              type: EventType.TOOL_CALL_RESULT,
              toolCallId: "live-wf",
              content: JSON.stringify({
                denied: true,
                reason: "The user denied permission for this action.",
              }),
            },
          });
        }
      });
      expect(closed).toHaveLength(1);

      // ActivityLog renders the computer_web_fetch entry
      view.rerender(
        <QueryClientProvider
          client={
            new QueryClient({ defaultOptions: { queries: { retry: false } } })
          }
        >
          <Harness
            messages={[
              {
                id: "a-live",
                role: "assistant",
                toolCalls: [
                  {
                    id: "live-wf",
                    type: "function",
                    function: {
                      name: "computer_web_fetch",
                      arguments: '{"url":"https://example.com"}',
                    },
                  },
                ],
              },
              {
                id: "r-live",
                role: "tool",
                toolCallId: "live-wf",
                content: JSON.stringify({
                  ok: true,
                  url: "https://example.com/",
                  title: "Live Example",
                }),
              },
            ]}
          />
        </QueryClientProvider>,
      );
      expect(view.getByText("Opened page")).toBeTruthy();
      expect(view.getByText("https://example.com/")).toBeTruthy();
    } finally {
      copilotSpy.mockRestore();
    }
  });
});

describe("Group Chat approvals, sidebar bot retention, and HTML preview", () => {
  const decisions: unknown[] = [];

  beforeEach(() => {
    decisions.length = 0;
  });

  test("GroupChat renders pending tool approval inline on desktop, allows approving, and populates ActivityLog", async () => {
    let approvalStatus = "pending";
    const workerId = "group-worker-1";
    const nowIso = new Date().toISOString();
    globalThis.fetch = (async (
      input: Parameters<typeof fetch>[0],
      init?: RequestInit,
    ) => {
      const url = new URL(String(input), "http://localhost");
      if (url.pathname === ME_PATH)
        return meResponse({
          user: { id: "me", role: "user", email: "me@example.test" },
        });
      const bots = answerBotsList(url, init, {
        visible: [
          { id: "commander", name: "Commander" },
          { id: workerId, name: "Worker" },
        ],
      });
      if (bots) return bots;
      const read = answerGroupRead(url, init, "group-1", {
        bots: [
          { id: "commander", name: "Commander" },
          { id: workerId, name: "Worker" },
        ],
        people: [
          { userId: "me", email: "me@example.test", name: null, creator: true },
        ],
        messages: [
          {
            id: "m-1",
            channelId: "group-1",
            ownerUserId: "me",
            agentId: null,
            text: "@Worker open example.com",
            status: "completed",
            createdAt: nowIso,
          },
          {
            id: "m-2",
            channelId: "group-1",
            ownerUserId: "me",
            agentId: workerId,
            text: "```html\n<!doctype html>\n<html><body><h1>Preview OK</h1></body></html>\n```",
            status: "completed",
            createdAt: nowIso,
          },
        ],
      });
      if (read) return read;
      if (init?.method === "POST" && url.pathname.endsWith("/decide")) {
        decisions.push(JSON.parse(String(init.body)));
        approvalStatus = "consumed";
        return (
          approvalWriteResponse(input, init) ?? Response.json({ ok: true })
        );
      }
      const approvals = approvalInboxResponse(url.pathname, {
        enabled: true,
        rules: [],
        teamRules: [],
        questions: [],
        requests: [
          {
            id: "appr-group-0",
            status: "completed",
            decision: "allow_once",
            createdAt: nowIso,
            decidedAt: nowIso,
            completedAt: nowIso,
            result: {
              ok: true,
              url: "https://previous.example/",
              title: "Previous",
            },
            action: {
              botId: workerId,
              toolRef: "computer_web_fetch",
              effect: "read",
              scope: "network",
              threadId: "thread-group-1",
              toolCallId: "tc-group-0",
              args: { url: "https://previous.example" },
            },
          },
          {
            id: "appr-group-1",
            status: approvalStatus,
            decision: approvalStatus === "pending" ? null : "allow_once",
            createdAt: nowIso,
            decidedAt: approvalStatus === "pending" ? null : nowIso,
            action: {
              botId: workerId,
              toolRef: "computer_web_fetch",
              effect: "read",
              scope: "network",
              threadId: "thread-group-1",
              toolCallId: "tc-group-1",
              args: { url: "https://example.com" },
              policy: {
                behaviour: "ask",
                source: "default",
                reason: "Opening web pages asks you first.",
              },
            },
          },
        ],
      });
      if (approvals) return approvals;
      return Response.json({ error: "not served" }, { status: 404 });
    }) as typeof fetch;

    const view = withQueries(
      <>
        <GroupChat channelId="group-1" threadId="thread-group-1" />
        <section aria-label="Worker activity">
          <ActivityLog computerId={workerId} />
        </section>
      </>,
    );

    const card = await view.findByRole("region", {
      name: "Waiting for your approval",
    });
    expect(
      within(card).getByText("Opening web pages asks you first."),
    ).toBeTruthy();

    // Completed group tool call is surfaced in Worker's ActivityLog
    await waitFor(() => {
      const log = within(view.getByRole("region", { name: "Worker activity" }));
      expect(log.getByText("Opened page")).toBeTruthy();
      expect(log.getByText("https://previous.example")).toBeTruthy();
      expect(log.getByText("Allowed once.")).toBeTruthy();
    });

    // Verify HTML code preview renders cleanly inside GroupChat too
    const previewBtn = await view.findByRole("button", { name: "Preview" });
    fireEvent.click(previewBtn);
    await waitFor(() => {
      const iframe = view.queryByTitle(
        "HTML preview",
      ) as HTMLIFrameElement | null;
      expect(iframe).not.toBeNull();
      expect(iframe!.getAttribute("sandbox")).toBe("allow-scripts");
      expect(iframe!.getAttribute("sandbox")).not.toContain(
        "allow-same-origin",
      );
    });

    // Approve the tool call directly in GroupChat
    fireEvent.click(within(card).getByRole("button", { name: "Allow once" }));
    await waitFor(() =>
      expect(decisions).toEqual([{ decision: "allow_once" }]),
    );

    // Status row indicates Worker is running the approved action
    await waitFor(() =>
      expect(view.getByRole("status").textContent).toContain(
        "Opening page · https://example.com",
      ),
    );
    expect(activityFor(workerId).map((e) => e.subject)).toEqual([
      "https://previous.example",
    ]);
  });

  test("selectGroupComputerBot remembers the bot that ran tools/spoke instead of snapping back to Commander", () => {
    const agentIds = ["commander", "worker"];
    expect(
      selectGroupComputerBot({
        agentIds,
        explicitBot: undefined,
        activeRunningBot: undefined,
        rememberedBot: "worker",
        latestApprovalBot: undefined,
        lastMessageBot: "commander",
      }),
    ).toBe("worker");

    expect(
      selectGroupComputerBot({
        agentIds,
        explicitBot: "commander",
        activeRunningBot: "worker",
        rememberedBot: "worker",
      }),
    ).toBe("commander");

    const latest = latestGroupApprovalBot(
      {
        enabled: true,
        rules: [],
        teamRules: [],
        questions: [],
        requests: [
          {
            id: "a-old",
            status: "completed",
            createdAt: "2026-11-17T10:00:00Z",
            action: {
              botId: "commander",
              toolRef: "computer_web_fetch",
              effect: "read",
              scope: "network",
              threadId: "t1",
            },
          },
          {
            id: "a-new",
            status: "completed",
            createdAt: "2026-11-17T10:05:00Z",
            action: {
              botId: "worker",
              toolRef: "computer_web_fetch",
              effect: "read",
              scope: "network",
              threadId: "t1",
            },
          },
        ],
      },
      "t1",
      agentIds,
    );
    expect(latest).toEqual({ requestId: "a-new", botId: "worker" });
  });
});

describe("ComputerView inline Page | Reader | Screen switcher and JS-only SPA fallback", () => {
  test("inline ComputerView exposes Page | Reader | Screen switcher and handles empty SPA text cleanly", async () => {
    globalThis.fetch = (async (input: Parameters<typeof fetch>[0]) => {
      const path = String(input);
      if (path.endsWith("/page")) {
        return Response.json({
          ok: true,
          url: "https://www.youtube.com/",
          title: "YouTube",
          text: "",
          html: "<!doctype html><html><body><ytd-app></ytd-app></body></html>",
          revision: 1,
          mode: "html-preview",
        });
      }
      if (path.endsWith("/screenshot")) {
        return Response.json({
          base64: "AAAA",
          width: 320,
          height: 200,
          capturedAt: new Date(0).toISOString(),
          url: "https://www.youtube.com/",
        });
      }
      if (path.endsWith("/control")) {
        return Response.json({
          holder: "bot",
          since: new Date(0).toISOString(),
          requested: false,
        });
      }
      if (path.endsWith("/status")) {
        return Response.json({ botId: "sales", state: "ready" });
      }
      return new Response("not found", { status: 404 });
    }) as typeof fetch;

    const view = withQueries(
      <ComputerView active computerId="sales" intervalMs={50} name="Sales" />,
    );

    const switcher = await view.findByRole("group", { name: "Page view mode" });
    const pageBtn = within(switcher).getByRole("button", { name: "Page" });
    const readerBtn = within(switcher).getByRole("button", { name: "Reader" });
    const screenBtn = within(switcher).getByRole("button", { name: "Screen" });

    expect(pageBtn.getAttribute("aria-pressed")).toBe("true");
    expect(view.getByTitle("YouTube")).toBeTruthy();

    // Switch to Reader inline — shows clear JS-only SPA note instead of blank screen
    fireEvent.click(readerBtn);
    expect(readerBtn.getAttribute("aria-pressed")).toBe("true");
    expect(
      await view.findByText(/No static text was extracted from this page/),
    ).toBeTruthy();
    // Modal did NOT accidentally open on clicking Reader
    expect(view.queryByRole("dialog", { name: "The Bot's screen" })).toBeNull();
    // Fullscreen expand remains reachable
    expect(
      view.getByRole("button", { name: "Open the Bot's screen full size" }),
    ).toBeTruthy();

    // Switch to Screen inline — renders screenshot img
    fireEvent.click(screenBtn);
    expect(screenBtn.getAttribute("aria-pressed")).toBe("true");
    expect(await view.findByAltText("What the Bot is looking at")).toBeTruthy();
  });
});
