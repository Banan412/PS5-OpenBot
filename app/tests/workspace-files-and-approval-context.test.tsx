import { afterAll, afterEach, beforeAll, expect, test } from "bun:test";
import { GlobalRegistrator } from "@happy-dom/global-registrator";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, cleanup, render, waitFor } from "@testing-library/react";
import { ToolLine } from "@/components/channels/tool-line";
import { ComputerViewPanel } from "@/components/computer/computer-panel";
import { WorkspaceFiles } from "@/components/computer/workspace-files";
import { showComputerFile } from "@/lib/computers/panel-view";
import {
  frontendApprovalSnapshot,
  observeApprovalAgent,
  parseToolArguments,
} from "@/lib/copilot/approval-context";
import { ME_PATH, meResponse } from "./accounts-api";

const FILES: Record<string, string> = {
  "notes.md": "# Notes\nRemember to ship the build.",
  "dashboard.html":
    "<!doctype html><html><body><h1>Live Report</h1></body></html>",
  "reports/summary.html": "<html><body><p>Q1 Summary</p></body></html>",
  "reports/data.csv": "month,total\nJan,42\n",
};

const FOLDERS: Record<
  string,
  Array<{ path: string; kind: "file" | "folder"; bytes?: number }>
> = {
  "": [
    { path: "reports", kind: "folder" },
    { path: "notes.md", kind: "file", bytes: FILES["notes.md"].length },
    {
      path: "dashboard.html",
      kind: "file",
      bytes: FILES["dashboard.html"].length,
    },
  ],
  reports: [
    {
      path: "reports/summary.html",
      kind: "file",
      bytes: FILES["reports/summary.html"].length,
    },
    {
      path: "reports/data.csv",
      kind: "file",
      bytes: FILES["reports/data.csv"].length,
    },
  ],
};

let originalFetch: typeof fetch;
const requests: Array<{ path: string; body: Record<string, unknown> }> = [];

beforeAll(() => {
  GlobalRegistrator.register();
  originalFetch = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = new URL(String(input), "http://openbot.test").pathname;
    if (path === ME_PATH) {
      return meResponse({ user: { id: "ada", name: "Ada" } });
    }
    if (path.includes("/control")) {
      return Response.json({
        holder: "bot",
        since: "2026-11-05T00:00:00.000Z",
        requested: false,
        transitioning: false,
        resumeSnapshotRequired: false,
        recoveryRequired: false,
        request: { id: "r1", status: "waiting", reason: "", source: "manual" },
      });
    }
    if (path.endsWith("/files/list")) {
      const parsed =
        typeof init?.body === "string"
          ? (JSON.parse(init.body) as { path?: string })
          : {};
      const dir = parsed.path ?? "";
      requests.push({ path, body: parsed });
      return Response.json({
        ok: true,
        path: dir,
        entries: FOLDERS[dir] ?? [],
        truncated: false,
      });
    }
    if (path.endsWith("/files/read")) {
      const parsed =
        typeof init?.body === "string"
          ? (JSON.parse(init.body) as { path?: string })
          : {};
      const filePath = parsed.path ?? "";
      requests.push({ path, body: parsed });
      const text = FILES[filePath];
      if (text === undefined) {
        return Response.json(
          { ok: false, reason: "file not found" },
          { status: 404 },
        );
      }
      return Response.json({
        ok: true,
        path: filePath,
        text,
        truncated: false,
        bytes: text.length,
      });
    }
    return Response.json({ error: "Not here." }, { status: 404 });
  }) as typeof fetch;
});

afterEach(() => {
  cleanup();
  requests.length = 0;
});

afterAll(() => {
  globalThis.fetch = originalFetch;
  GlobalRegistrator.unregister();
});

function renderWithQueries(ui: React.ReactElement) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>{ui}</QueryClientProvider>,
  );
}

test("parseToolArguments and frontendApprovalSnapshot handle partial or malformed JSON safely", () => {
  expect(
    parseToolArguments('{"path":"notes.md","contents":"unterminated'),
  ).toEqual({});
  expect(parseToolArguments("")).toEqual({});
  expect(parseToolArguments("null")).toEqual({});
  expect(parseToolArguments("[1, 2, 3]")).toEqual({});
  expect(parseToolArguments('{"path":"notes.md"}')).toEqual({
    path: "notes.md",
  });

  const subscribers: Array<{
    onRunStartedEvent?: (payload: {
      input: {
        runId: string;
        threadId: string;
        context: unknown[];
        forwardedProps: Record<string, unknown>;
      };
      event: { runId: string; threadId: string };
    }) => void;
  }> = [];

  const fakeAgent = {
    threadId: "thread-1",
    messages: [],
    state: {},
    subscribe(sub: (typeof subscribers)[number]) {
      subscribers.push(sub);
      return { unsubscribe() {} };
    },
  } as unknown as Parameters<typeof observeApprovalAgent>[0];

  const release = observeApprovalAgent(fakeAgent);
  subscribers[0]?.onRunStartedEvent?.({
    input: {
      runId: "run-0",
      threadId: "thread-1",
      context: [],
      forwardedProps: {},
    },
    event: { runId: "run-1", threadId: "thread-1" },
  });

  const snapshot = frontendApprovalSnapshot({
    agent: fakeAgent,
    toolCall: {
      id: "call-partial",
      type: "function",
      function: {
        name: "computer_write_file",
        arguments: '{"path":"notes.md","contents":"cut off mid stream',
      },
    },
  } as unknown as Parameters<typeof frontendApprovalSnapshot>[0]);

  expect(snapshot.toolName).toBe("computer_write_file");
  expect(snapshot.args).toEqual({});
  expect(snapshot.runId).toBe("run-1");
  release();
});

test("ComputerViewPanel Files tab lists directories, navigates folders, previews HTML safely, and downloads", async () => {
  const originalCreateObjectURL = URL.createObjectURL;
  const originalRevokeObjectURL = URL.revokeObjectURL;
  const downloaded: Array<{ blob: Blob; filename: string }> = [];
  let createdUrl = "";

  URL.createObjectURL = ((blob: Blob) => {
    createdUrl = "blob:test-download";
    downloaded.push({ blob, filename: "" });
    return createdUrl;
  }) as typeof URL.createObjectURL;
  URL.revokeObjectURL = (() => {}) as typeof URL.revokeObjectURL;

  try {
    renderWithQueries(<ComputerViewPanel agentId="files-bot" />);

    const filesTab = await waitFor(() => {
      const tab = [...document.querySelectorAll('[role="tab"]')].find(
        (candidate) => candidate.textContent?.trim() === "Files",
      );
      expect(tab).toBeDefined();
      return tab as HTMLElement;
    });

    act(() => filesTab.click());

    await waitFor(() => {
      expect(document.body.textContent).toContain("reports");
      expect(document.body.textContent).toContain("dashboard.html");
      expect(document.body.textContent).toContain("notes.md");
    });

    // Navigate into folder
    const reportsBtn = [...document.querySelectorAll("button")].find((b) =>
      b.textContent?.includes("reports"),
    ) as HTMLButtonElement;
    act(() => reportsBtn.click());

    await waitFor(() => {
      expect(document.body.textContent).toContain("summary.html");
      expect(document.body.textContent).toContain("data.csv");
    });

    // Navigate back to Workspace root
    const rootBtn = [...document.querySelectorAll("button")].find(
      (b) => b.textContent?.trim() === "Workspace",
    ) as HTMLButtonElement;
    act(() => rootBtn.click());

    await waitFor(() => {
      expect(document.body.textContent).toContain("dashboard.html");
    });

    // Click HTML file to open preview
    const htmlBtn = [...document.querySelectorAll("button")].find((b) =>
      b.textContent?.includes("dashboard.html"),
    ) as HTMLButtonElement;
    act(() => htmlBtn.click());

    const iframe = await waitFor(() => {
      const el = document.querySelector("iframe");
      expect(el).not.toBeNull();
      return el as HTMLIFrameElement;
    });
    expect(iframe.getAttribute("sandbox")).toBe("allow-scripts");
    expect(iframe.getAttribute("sandbox")).not.toContain("allow-same-origin");
    expect(iframe.getAttribute("srcdoc")).toContain("<h1>Live Report</h1>");

    // Toggle to Code view
    const codeBtn = [...document.querySelectorAll("button")].find(
      (b) => b.textContent?.trim() === "Code",
    ) as HTMLButtonElement;
    act(() => codeBtn.click());

    await waitFor(() => {
      expect(document.querySelector("iframe")).toBeNull();
      expect(document.querySelector("pre code")?.textContent).toContain(
        "<!doctype html>",
      );
    });

    // Download file
    const downloadBtn = document.querySelector(
      'button[aria-label="Download dashboard.html"]',
    ) as HTMLButtonElement;
    expect(downloadBtn).not.toBeNull();
    act(() => downloadBtn.click());
    expect(downloaded.length).toBe(1);
    expect(await downloaded[0]?.blob.text()).toBe(FILES["dashboard.html"]);
  } finally {
    URL.createObjectURL = originalCreateObjectURL;
    URL.revokeObjectURL = originalRevokeObjectURL;
  }
});

test("clicking a file detail in ToolLine or calling showComputerFile opens the Files tab and selects the file", async () => {
  renderWithQueries(<ComputerViewPanel agentId="jump-bot" />);
  render(
    <ToolLine
      detail="reports/summary.html"
      detailTitle="Open reports/summary.html in Workspace Files"
      label="Saved a file"
      onDetailClick={() => showComputerFile("jump-bot", "reports/summary.html")}
    />,
  );

  await waitFor(() => {
    const tabs = [...document.querySelectorAll('[role="tab"]')];
    expect(tabs.some((t) => t.textContent?.trim() === "Files")).toBe(true);
  });

  const fileLink = [...document.querySelectorAll("button")].find(
    (b) => b.textContent?.trim() === "reports/summary.html",
  ) as HTMLButtonElement;
  expect(fileLink).toBeDefined();
  act(() => fileLink.click());

  await waitFor(() => {
    const selectedTabs = [...document.querySelectorAll('[role="tab"]')]
      .filter((tab) => tab.getAttribute("aria-selected") === "true")
      .map((tab) => tab.textContent?.trim());
    expect(selectedTabs).toEqual(["Files"]);
  });

  const iframe = await waitFor(() => {
    const el = document.querySelector("iframe");
    expect(el).not.toBeNull();
    return el as HTMLIFrameElement;
  });
  expect(iframe.getAttribute("srcdoc")).toContain("Q1 Summary");
});

test("WorkspaceFiles shows clean recovery message when listing fails", async () => {
  const savedFetch = globalThis.fetch;
  globalThis.fetch = (async () =>
    Response.json(
      { ok: false, reason: "workspace unavailable" },
      { status: 500 },
    )) as unknown as typeof fetch;

  try {
    render(<WorkspaceFiles computerId="broken-bot" />);
    await waitFor(() => {
      expect(document.body.textContent).toContain("Retry");
    });
  } finally {
    globalThis.fetch = savedFetch;
  }
});
