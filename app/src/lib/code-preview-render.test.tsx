import { afterAll, afterEach, beforeAll, expect, test } from "bun:test";
import { GlobalRegistrator } from "@happy-dom/global-registrator";
import { cleanup, fireEvent, render, waitFor } from "@testing-library/react";
import {
  BotMarkdown,
  markdownComponents,
  markdownPlugins,
} from "@/lib/markdown";
import { settleReactWork } from "../../tests/settle-react-work";

beforeAll(() => {
  GlobalRegistrator.register({ url: "http://localhost/" });
});

afterEach(() => {
  cleanup();
});

afterAll(async () => {
  await settleReactWork();
  GlobalRegistrator.unregister();
});

test("HTML code block renders Preview/Code toggle and mounts sandboxed iframe without allow-same-origin", async () => {
  const md = [
    "Here is a widget:",
    "",
    "```html",
    "<!doctype html>",
    "<html><body><h1>Hello Preview</h1></body></html>",
    "```",
  ].join("\n");

  const { container, getByRole, queryByTitle } = render(
    <BotMarkdown
      components={markdownComponents}
      mode="static"
      plugins={markdownPlugins}
    >
      {md}
    </BotMarkdown>,
  );

  const previewBtn = getByRole("button", { name: "Preview" });
  const codeBtn = getByRole("button", { name: "Code" });
  expect(previewBtn.getAttribute("aria-pressed")).toBe("false");
  expect(codeBtn.getAttribute("aria-pressed")).toBe("true");
  expect(queryByTitle("HTML preview")).toBeNull();
  expect(
    container.querySelector('[data-streamdown="code-block-copy-button"]'),
  ).not.toBeNull();
  expect(
    container.querySelector('[data-streamdown="code-block-download-button"]'),
  ).not.toBeNull();

  fireEvent.click(previewBtn);

  await waitFor(() => {
    const iframe = queryByTitle("HTML preview") as HTMLIFrameElement | null;
    expect(iframe).not.toBeNull();
    expect(iframe!.getAttribute("sandbox")).toBe("allow-scripts");
    expect(iframe!.getAttribute("sandbox")).not.toContain("allow-same-origin");
    expect(iframe!.getAttribute("srcdoc")).toContain("<h1>Hello Preview</h1>");
  });

  expect(
    container.querySelector('[data-streamdown="code-block-copy-button"]'),
  ).not.toBeNull();
  expect(
    container.querySelector('[data-streamdown="code-block-download-button"]'),
  ).not.toBeNull();

  const expandBtn = getByRole("button", { name: "Expand preview height" });
  expect(expandBtn.getAttribute("aria-pressed")).toBe("false");
  fireEvent.click(expandBtn);
  expect(
    getByRole("button", { name: "Collapse preview height" }).getAttribute(
      "aria-pressed",
    ),
  ).toBe("true");

  fireEvent.click(getByRole("button", { name: "Code" }));
  expect(queryByTitle("HTML preview")).toBeNull();
});

test("SVG code block wraps markup in centered shell inside sandboxed iframe", async () => {
  const md = [
    "```svg",
    '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/></svg>',
    "```",
  ].join("\n");

  const { getByRole, queryByTitle } = render(
    <BotMarkdown
      components={markdownComponents}
      mode="static"
      plugins={markdownPlugins}
    >
      {md}
    </BotMarkdown>,
  );

  fireEvent.click(getByRole("button", { name: "Preview" }));

  await waitFor(() => {
    const iframe = queryByTitle("SVG preview") as HTMLIFrameElement | null;
    expect(iframe).not.toBeNull();
    expect(iframe!.getAttribute("sandbox")).toBe("allow-scripts");
    expect(iframe!.getAttribute("srcdoc")).toContain("justify-content: center");
    expect(iframe!.getAttribute("srcdoc")).toContain('<circle cx="12" cy="12" r="10"/>');
  });
});

test("non-previewable python block does not show Preview/Code toggle", () => {
  const md = ["```python", "print('<html>hello</html>')", "```"].join("\n");

  const { container, queryByRole } = render(
    <BotMarkdown
      components={markdownComponents}
      mode="static"
      plugins={markdownPlugins}
    >
      {md}
    </BotMarkdown>,
  );

  expect(queryByRole("button", { name: "Preview" })).toBeNull();
  expect(
    container.querySelector('[data-streamdown="code-block"]'),
  ).not.toBeNull();
});

test("streaming unclosed html fence shows streaming indicator and disables Preview until closed", () => {
  const md = ["```html", "<div>Still streaming"].join("\n");

  const { container, getByRole } = render(
    <BotMarkdown
      components={markdownComponents}
      isAnimating={true}
      mode="streaming"
      plugins={markdownPlugins}
    >
      {md}
    </BotMarkdown>,
  );

  expect(
    container.querySelector('[data-openbot-preview-streaming="true"]'),
  ).not.toBeNull();
  const previewBtn = getByRole("button", {
    name: "Preview",
  }) as HTMLButtonElement;
  expect(previewBtn.disabled).toBe(true);
});
