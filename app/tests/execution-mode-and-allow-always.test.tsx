import {
  afterAll,
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  test,
} from "bun:test";
import { GlobalRegistrator } from "@happy-dom/global-registrator";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  createMemoryHistory,
  createRootRoute,
  createRoute,
  createRouter,
  RouterProvider,
} from "@tanstack/react-router";
import {
  cleanup,
  fireEvent,
  render,
  waitFor,
  within,
} from "@testing-library/react";
import type { ReactElement } from "react";
import { ExecutionModeSelector } from "@/components/approvals/execution-mode-selector";
import {
  ConversationApprovals,
  InlineApproval,
} from "@/components/approvals/inline-approval";
import { ApprovalSettings } from "@/components/approvals/settings";
import { TeamApprovalSettings } from "@/components/approvals/team-settings";
import { ConversationView } from "@/components/channels/conversation-view";
import { GroupChat } from "@/components/channels/group-chat";
import { TooltipProvider } from "@/components/ui/tooltip";
import { deploymentKeys } from "@/lib/deployment/queries";
import { setCurrentOrganization } from "@/lib/organizations/current";
import { ME_PATH, meResponse } from "./accounts-api";
import {
  APPROVAL_SETTINGS_PATH,
  approvalInboxResponse,
  approvalWriteResponse,
} from "./approvals-api";
import { answerBotsList } from "./bots-api";
import { answerGroupRead } from "./conversations-api";
import { settleReactWork } from "./settle-react-work";

let originalFetch: typeof fetch;
let originalWebSocket: typeof WebSocket;

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
  globalThis.WebSocket = QuietSocket as unknown as typeof WebSocket;
});

afterEach(() => {
  cleanup();
  setCurrentOrganization(undefined);
  globalThis.fetch = originalFetch;
});

afterAll(async () => {
  await settleReactWork();
  globalThis.fetch = originalFetch;
  globalThis.WebSocket = originalWebSocket;
  GlobalRegistrator.unregister();
});

function withQueries(ui: ReactElement) {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={qc}>
      <TooltipProvider delay={0}>{ui}</TooltipProvider>
    </QueryClientProvider>,
  );
}

describe("ExecutionModeSelector & Settings integration", () => {
  const patches: {
    path: string;
    body: unknown;
    idempotencyKey: string | null;
  }[] = [];

  beforeEach(() => {
    patches.length = 0;
    setCurrentOrganization("default");
  });

  test("ExecutionModeSelector loads executionMode and PATCHes approval-settings on toggle", async () => {
    let mode: "ask" | "auto" | "turbo" = "auto";
    globalThis.fetch = Object.assign(
      async (input: Parameters<typeof fetch>[0], init?: RequestInit) => {
        const url = new URL(String(input), "http://localhost");
        if (url.pathname === APPROVAL_SETTINGS_PATH) {
          if (init?.method === "PATCH") {
            const body = JSON.parse(String(init.body)) as {
              executionMode: "ask" | "auto" | "turbo";
            };
            const headers = new Headers(init.headers);
            patches.push({
              path: url.pathname,
              body,
              idempotencyKey: headers.get("Idempotency-Key"),
            });
            mode = body.executionMode;
            return approvalWriteResponse(url.pathname, init, {
              team: { executionMode: mode },
            })!;
          }
          return approvalInboxResponse(url.pathname, {
            team: { executionMode: mode },
          })!;
        }
        return new Response(null, { status: 404 });
      },
      { preconnect: originalFetch.preconnect },
    );

    const view = withQueries(<ExecutionModeSelector />);
    const group = await view.findByRole("group", { name: "Execution mode" });
    const askBtn = within(group).getByRole("button", { name: "Ask" });
    const autoBtn = within(group).getByRole("button", { name: "Auto" });
    const turboBtn = within(group).getByRole("button", { name: "Turbo" });

    await waitFor(() => {
      expect(autoBtn.getAttribute("aria-pressed")).toBe("true");
    });

    fireEvent.click(turboBtn);
    await waitFor(() => {
      expect(patches).toHaveLength(1);
      expect(patches[0]?.path).toBe(APPROVAL_SETTINGS_PATH);
      expect(patches[0]?.body).toEqual({ executionMode: "turbo" });
      expect(patches[0]?.idempotencyKey).toBeTruthy();
      expect(turboBtn.getAttribute("aria-pressed")).toBe("true");
    });

    fireEvent.click(askBtn);
    await waitFor(() => {
      expect(patches).toHaveLength(2);
      expect(patches[1]?.body).toEqual({ executionMode: "ask" });
      expect(askBtn.getAttribute("aria-pressed")).toBe("true");
    });
  });

  test("ConversationView and GroupChat both expose Ask | Auto | Turbo selector in composer toolbar", async () => {
    let mode: "ask" | "auto" | "turbo" = "ask";
    globalThis.fetch = Object.assign(
      async (input: Parameters<typeof fetch>[0], init?: RequestInit) => {
        const url = new URL(String(input), "http://localhost");
        if (url.pathname === ME_PATH)
          return meResponse({
            user: { id: "me", role: "owner", email: "me@example.test" },
          });
        if (
          url.pathname === APPROVAL_SETTINGS_PATH &&
          init?.method === "PATCH"
        ) {
          const body = JSON.parse(String(init.body)) as {
            executionMode: "ask" | "auto" | "turbo";
          };
          patches.push({
            path: url.pathname,
            body,
            idempotencyKey: new Headers(init.headers).get("Idempotency-Key"),
          });
          mode = body.executionMode;
          return approvalWriteResponse(url.pathname, init, {
            team: { executionMode: mode },
          })!;
        }
        const approvals = approvalInboxResponse(url.pathname, {
          team: { executionMode: mode },
          requests: [],
          rules: [],
          teamRules: [],
          questions: [],
        });
        if (approvals) return approvals;
        const bots = answerBotsList(url, init, {
          visible: [{ id: "bot-1", name: "Bot" }],
        });
        if (bots) return bots;
        const group = answerGroupRead(url, init, "g-exec", {
          bots: [{ id: "bot-1", name: "Bot" }],
          people: [
            {
              userId: "me",
              email: "me@example.test",
              name: null,
              creator: true,
            },
          ],
          messages: [],
        });
        if (group) return group;
        return new Response(null, { status: 404 });
      },
      { preconnect: originalFetch.preconnect },
    );

    const dmView = withQueries(
      <ConversationView channelId="c-exec" messages={[]} onSubmit={() => {}} />,
    );
    const dmSelector = await dmView.findByRole("group", {
      name: "Execution mode",
    });
    fireEvent.click(within(dmSelector).getByRole("button", { name: "Auto" }));
    await waitFor(() => {
      expect(patches[0]?.body).toEqual({ executionMode: "auto" });
    });
    cleanup();

    const groupView = withQueries(<GroupChat channelId="g-exec" />);
    const groupSelector = await groupView.findByRole("group", {
      name: "Execution mode",
    });
    await waitFor(() => {
      expect(
        within(groupSelector)
          .getByRole("button", { name: "Auto" })
          .getAttribute("aria-pressed"),
      ).toBe("true");
    });
    fireEvent.click(
      within(groupSelector).getByRole("button", { name: "Turbo" }),
    );
    await waitFor(() => {
      expect(patches[1]?.body).toEqual({ executionMode: "turbo" });
    });
  });

  test("TeamApprovalSettings and ApprovalSettings render Execution mode cleanly", async () => {
    let role: "admin" | "member" = "admin";
    let mode: "ask" | "auto" | "turbo" = "ask";
    globalThis.fetch = Object.assign(
      async (input: Parameters<typeof fetch>[0], init?: RequestInit) => {
        const url = new URL(String(input), "http://localhost");
        if (url.pathname === ME_PATH)
          return meResponse({
            user: { id: "me", role, email: "me@example.test" },
          });
        if (
          url.pathname === APPROVAL_SETTINGS_PATH &&
          init?.method === "PATCH"
        ) {
          const body = JSON.parse(String(init.body)) as {
            executionMode: "ask" | "auto" | "turbo";
          };
          patches.push({
            path: url.pathname,
            body,
            idempotencyKey: new Headers(init.headers).get("Idempotency-Key"),
          });
          mode = body.executionMode;
          return approvalWriteResponse(url.pathname, init, {
            team: { executionMode: mode },
          })!;
        }
        const approvals = approvalInboxResponse(url.pathname, {
          team: { executionMode: mode },
        });
        if (approvals) return approvals;
        const bots = answerBotsList(url, init, { visible: [] });
        if (bots) return bots;
        if (
          url.pathname === "/api/v2/organizations/default/shared-use-requests"
        )
          return Response.json({ sharedUseRequests: [], nextCursor: null });
        return new Response(null, { status: 404 });
      },
      { preconnect: originalFetch.preconnect },
    );

    const drawInRouter = (component: () => ReactElement) => {
      const qc = new QueryClient({
        defaultOptions: { queries: { retry: false } },
      });
      qc.setQueryData(deploymentKeys.capabilities(), { edition: "team" });
      const root = createRootRoute({ component });
      const describe = createRoute({
        path: "/admin/approvals/describe",
        getParentRoute: () => root,
        component: () => null,
      });
      const router = createRouter({
        routeTree: root.addChildren([describe]),
        history: createMemoryHistory({ initialEntries: ["/"] }),
      });
      return render(
        <QueryClientProvider client={qc}>
          <TooltipProvider delay={0}>
            <RouterProvider router={router as never} />
          </TooltipProvider>
        </QueryClientProvider>,
      );
    };

    const teamView = drawInRouter(() => <TeamApprovalSettings />);
    const teamGroup = await teamView.findByRole("group", {
      name: "Execution mode",
    });
    fireEvent.click(within(teamGroup).getByRole("button", { name: "Turbo" }));
    await waitFor(() => {
      expect(patches[0]?.body).toEqual({ executionMode: "turbo" });
    });
    cleanup();

    role = "member";
    const memberView = drawInRouter(() => <ApprovalSettings />);
    const memberGroup = await memberView.findByRole("group", {
      name: "Execution mode",
    });
    await waitFor(() => {
      expect(
        within(memberGroup)
          .getByRole("button", { name: "Turbo" })
          .hasAttribute("disabled"),
      ).toBe(true);
    });
  });
});

describe("Allow always decision in DM and Group approval cards", () => {
  beforeEach(() => {
    setCurrentOrganization("default");
  });

  test("submitting Always allow here sends decision=allow_always in DM and Group (with or without toolCallId)", async () => {
    const decisions: { id: string; decision: string }[] = [];
    const nowIso = new Date().toISOString();

    globalThis.fetch = Object.assign(
      async (input: Parameters<typeof fetch>[0], init?: RequestInit) => {
        const url = new URL(String(input), "http://localhost");
        if (init?.method === "POST" && url.pathname.endsWith("/decide")) {
          const id = decodeURIComponent(url.pathname.split("/").at(-2) ?? "");
          const body = JSON.parse(String(init.body)) as { decision: string };
          decisions.push({ id, decision: body.decision });
          return approvalWriteResponse(url.pathname, init)!;
        }
        const approvals = approvalInboxResponse(url.pathname, {
          requests: [
            {
              id: "dm-req-1",
              status: "pending",
              createdAt: nowIso,
              action: {
                botId: "assistant",
                toolRef: "computer_web_fetch",
                effect: "read",
                scope: "network",
                threadId: "thread-dm",
                toolCallId: "tc-dm-1",
                args: { url: "https://example.com" },
                policy: {
                  behaviour: "ask",
                  source: "default",
                  reason: "Opening web pages asks you first.",
                },
              },
            },
            {
              id: "group-req-no-tc",
              status: "pending",
              createdAt: nowIso,
              action: {
                botId: "worker",
                toolRef: "computer_web_fetch",
                effect: "read",
                scope: "network",
                threadId: "thread-group",
                args: { url: "https://docs.example.com" },
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
        return new Response(null, { status: 404 });
      },
      { preconnect: originalFetch.preconnect },
    );

    // DM InlineApproval
    const dmView = withQueries(
      <InlineApproval toolCallId="tc-dm-1" fallback={null} />,
    );
    const dmCard = within(
      await dmView.findByRole("region", { name: "Waiting for your approval" }),
    );
    fireEvent.click(dmCard.getByRole("radio", { name: "Always allow here" }));
    fireEvent.click(dmCard.getByRole("button", { name: "Always allow here" }));
    await waitFor(() => {
      expect(decisions).toContainEqual({
        id: "dm-req-1",
        decision: "allow_always",
      });
    });
    cleanup();

    // Group ConversationApprovals (even when toolCallId is omitted)
    const groupView = withQueries(
      <ConversationApprovals threadId="thread-group" />,
    );
    const groupCard = within(
      await groupView.findByRole("region", {
        name: "Waiting for your approval",
      }),
    );
    fireEvent.click(
      groupCard.getByRole("radio", { name: "Always allow here" }),
    );
    fireEvent.click(
      groupCard.getByRole("button", { name: "Always allow here" }),
    );
    await waitFor(() => {
      expect(decisions).toContainEqual({
        id: "group-req-no-tc",
        decision: "allow_always",
      });
    });
  });
});
