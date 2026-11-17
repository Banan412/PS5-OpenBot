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
import { cleanup, fireEvent, render, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactElement } from "react";
import { Composer } from "@/components/channels/composer/composer";
import type { ComposerDraft } from "@/components/channels/composer/draft";
import { ConversationView } from "@/components/channels/conversation-view";
import { GroupChat } from "@/components/channels/group-chat";
import { SendModeRow } from "@/components/settings/send-mode-row";
import { TooltipProvider } from "@/components/ui/tooltip";
import { setCurrentOrganization } from "@/lib/organizations/current";
import {
  getSendMode,
  SEND_MODE_STORAGE_KEY,
  setSendMode,
} from "@/lib/settings/send-mode";
import { ME_PATH, meResponse } from "./accounts-api";
import { answerBotsList } from "./bots-api";
import {
  answerGroupRead,
  conversationPath,
  problem,
} from "./conversations-api";
import { settleReactWork } from "./settle-react-work";

const NativeResponse = globalThis.Response;
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

beforeEach(() => {
  window.localStorage.clear();
  setSendMode("queue");
  setCurrentOrganization("default");
  globalThis.fetch = (async () =>
    problem(404, "Not found.")) as unknown as typeof fetch;
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

function renderWithProviders(ui: ReactElement) {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={qc}>
      <TooltipProvider delay={0}>{ui}</TooltipProvider>
    </QueryClientProvider>,
  );
}

describe("send-mode preference & Composer instant send", () => {
  test("persists send mode choice to localStorage and switches Composer between Queue and Instant", async () => {
    expect(getSendMode()).toBe("queue");

    const queued: string[] = [];
    const sentNow: string[] = [];
    const view = render(
      <Composer
        compact
        onQueue={(draft) => queued.push(draft.text)}
        onSendNow={async (draft) => {
          sentNow.push(draft.text);
        }}
        onSubmit={async () => {}}
        pending
      />,
    );

    const user = userEvent.setup({ document: view.container.ownerDocument });
    const box = view.getByRole("textbox", { name: "Message" });

    // In Queue mode while busy: typing enables both "Queue message" and inline "Send now".
    await user.type(box, "interrupt and run this");
    expect(view.getByRole("button", { name: "Queue message" })).toBeTruthy();
    await user.click(view.getByRole("button", { name: "Send now" }));

    await waitFor(() => expect(sentNow).toEqual(["interrupt and run this"]));
    expect(queued).toEqual([]);

    // Switch toggle to Instant: primary button becomes "Send now" and Enter sends immediately.
    await user.click(view.getByRole("button", { name: "Send mode: Instant" }));
    expect(getSendMode()).toBe("instant");
    expect(window.localStorage.getItem(SEND_MODE_STORAGE_KEY)).toBe("instant");

    await user.type(box, "second instant message");
    const submitBtn = view.getByRole("button", { name: "Send now" });
    expect(submitBtn.getAttribute("type")).toBe("submit");
    await user.click(submitBtn);

    await waitFor(() =>
      expect(sentNow).toEqual([
        "interrupt and run this",
        "second instant message",
      ]),
    );
    expect(queued).toEqual([]);
  });

  test("an earlier hung onSubmit does not block Send now from running immediately", async () => {
    let releaseFirst!: () => void;
    const firstTurn = new Promise<void>((resolve) => {
      releaseFirst = resolve;
    });
    const sentNow: string[] = [];

    const view = render(
      <Composer
        compact
        onQueue={() => {}}
        onSendNow={async (draft) => {
          sentNow.push(draft.text);
        }}
        onSubmit={() => firstTurn}
      />,
    );

    const user = userEvent.setup({ document: view.container.ownerDocument });
    const box = view.getByRole("textbox", { name: "Message" });

    // Start first turn (stays pending forever until released).
    await user.type(box, "first hung message");
    await user.click(view.getByRole("button", { name: "Send message" }));

    // While first turn is still awaiting, Send now must still work immediately.
    await user.type(box, "rescue now");
    await user.click(view.getByRole("button", { name: "Send now" }));

    await waitFor(() => expect(sentNow).toEqual(["rescue now"]));
    releaseFirst();
    await firstTurn;
  });

  test("Settings SendModeRow persists send mode and stays synced with Composer", async () => {
    const view = renderWithProviders(
      <div>
        <SendModeRow />
        <Composer
          compact
          onQueue={() => {}}
          onSendNow={async () => {}}
          onSubmit={async () => {}}
        />
      </div>,
    );

    const user = userEvent.setup({ document: view.container.ownerDocument });
    const trigger = view.getByRole("combobox", {
      name: "Send mode while busy",
    });
    await user.click(trigger);
    await user.click(
      await view.findByRole("option", { name: "Instant (interrupt & send)" }),
    );

    expect(getSendMode()).toBe("instant");
    expect(
      view
        .getByRole("button", { name: "Send mode: Instant" })
        .getAttribute("aria-pressed"),
    ).toBe("true");
  });
});

describe("ConversationView & Queued card Send now", () => {
  test("queued card renders 'Send now' and clicking it sends immediately even when stuck/heldBack", async () => {
    globalThis.fetch = (async () =>
      problem(404, "Not found.")) as unknown as typeof fetch;

    const sentNow: string[] = [];
    const view = renderWithProviders(
      <ConversationView
        channelId="channel-1"
        messages={[]}
        onSendNow={async (draft: ComposerDraft) => {
          sentNow.push(draft.text);
        }}
        onSubmit={async () => {}}
        pending
        queueWhileBusy
      />,
    );

    const user = userEvent.setup({ document: view.container.ownerDocument });
    const box = view.getByRole("textbox", { name: "Message" });

    await user.type(box, "Message one");
    await user.click(view.getByRole("button", { name: "Queue message" }));

    await user.type(box, "Message two");
    await user.click(view.getByRole("button", { name: "Queue message" }));

    const sendQueuedOne = await view.findByRole("button", {
      name: "Send queued message now: Message one",
    });
    expect(
      view.getByRole("button", {
        name: "Send queued message now: Message two",
      }),
    ).toBeTruthy();

    await user.click(sendQueuedOne);

    await waitFor(() => expect(sentNow).toEqual(["Message one"]));
    // Second queued message stays safely queued until drained or sent now.
    expect(
      view.queryByRole("button", {
        name: "Send queued message now: Message one",
      }),
    ).toBeNull();
    expect(
      view.getByRole("button", {
        name: "Send queued message now: Message two",
      }),
    ).toBeTruthy();
  });

  test("composer Send now drains earlier queued messages in order alongside the current draft", async () => {
    globalThis.fetch = (async () =>
      problem(404, "Not found.")) as unknown as typeof fetch;

    const sentNow: string[] = [];
    const view = renderWithProviders(
      <ConversationView
        channelId="channel-1"
        messages={[]}
        onSendNow={async (draft: ComposerDraft) => {
          sentNow.push(draft.text);
        }}
        onSubmit={async () => {}}
        pending
        queueWhileBusy
      />,
    );

    const user = userEvent.setup({ document: view.container.ownerDocument });
    const box = view.getByRole("textbox", { name: "Message" });

    await user.type(box, "First parked");
    await user.click(view.getByRole("button", { name: "Queue message" }));

    await user.type(box, "Second instant");
    await user.click(view.getByRole("button", { name: "Send now" }));

    await waitFor(() =>
      expect(sentNow).toEqual(["First parked\nSecond instant"]),
    );
    expect(
      view.queryByRole("button", {
        name: /^Send queued message now:/,
      }),
    ).toBeNull();
  });
});

describe("GroupChat instant send while Programmer is busy/stuck", () => {
  test("offers Send now while a bot is running and sends interruptActive: true", async () => {
    const postedBodies: Record<string, unknown>[] = [];
    const groupFixture = {
      bots: [
        { id: "bot-lead", name: "Lead" },
        { id: "bot-prog", name: "Programmer" },
      ],
      people: [
        {
          userId: "user-1",
          email: "owner@example.com",
          name: "Owner",
          creator: true,
        },
      ],
      messages: [
        {
          id: "m-user-1",
          ownerUserId: "user-1",
          agentId: null,
          text: "@Programmer write hello.txt",
          status: "completed",
          createdAt: "2026-11-17T18:00:00Z",
        },
        {
          id: "m-prog-1",
          ownerUserId: "user-1",
          agentId: "bot-prog",
          text: "",
          status: "running",
          createdAt: "2026-11-17T18:00:01Z",
        },
      ],
    };

    globalThis.fetch = (async (
      input: RequestInfo | URL,
      init?: RequestInit,
    ) => {
      const url = new URL(String(input), "http://localhost");
      if (url.pathname === ME_PATH) {
        return NativeResponse.json(meResponse({ user: { id: "user-1" } }));
      }
      const groupResp = answerGroupRead(input, init, "group-1", groupFixture);
      if (groupResp) return groupResp;
      const botsResp = answerBotsList(input, init, {
        visible: [
          { id: "bot-lead", name: "Lead" },
          { id: "bot-prog", name: "Programmer" },
        ],
      });
      if (botsResp) return botsResp;
      if (
        url.pathname === conversationPath("group-1", "/messages") &&
        (init?.method ?? "GET").toUpperCase() === "POST"
      ) {
        const parsed = JSON.parse(String(init?.body ?? "{}")) as Record<
          string,
          unknown
        >;
        postedBodies.push(parsed);
        return NativeResponse.json(
          { id: parsed.id ?? "msg-new", queued: false },
          { status: 202 },
        );
      }
      return problem(404, "Not found.");
    }) as unknown as typeof fetch;

    const view = renderWithProviders(<GroupChat channelId="group-1" />);

    const box = await view.findByRole("textbox", { name: "Message" });
    // Even though Programmer is "running", user can type and click "Send now".
    fireEvent.input(box, { target: { textContent: "check status now" } });
    const user = userEvent.setup({ document: view.container.ownerDocument });
    await user.click(box);
    await user.type(box, "please reply");

    const sendNowBtn = await view.findByRole("button", { name: "Send now" });
    await user.click(sendNowBtn);

    await waitFor(() => expect(postedBodies).toHaveLength(1));
    expect(postedBodies[0]).toMatchObject({
      interruptActive: true,
      text: expect.stringContaining("please reply"),
    });
  });
});
