import { expect, test } from "bun:test";
import {
  buildPreviewDocument,
  extractCodeLanguage,
  isPreviewableCode,
} from "./code-preview";

test("isPreviewableCode detects explicit html, htm, xhtml, and svg fences", () => {
  expect(isPreviewableCode("html", "<h1>Hello</h1>")).toBe("html");
  expect(isPreviewableCode("HTML", "<div>World</div>")).toBe("html");
  expect(isPreviewableCode(" htm ", "<p>Hi</p>")).toBe("html");
  expect(isPreviewableCode("xhtml", "<html xmlns='http://www.w3.org/1999/xhtml'></html>")).toBe(
    "html",
  );
  expect(
    isPreviewableCode("svg", '<svg viewBox="0 0 10 10"><circle cx="5" cy="5" r="4"/></svg>'),
  ).toBe("svg");
  expect(isPreviewableCode(" SVG ", "<svg></svg>")).toBe("svg");
});

test("isPreviewableCode detects xml and plain blocks containing html or svg", () => {
  expect(
    isPreviewableCode(
      undefined,
      "<!doctype html>\n<html><body><h1>Page</h1></body></html>",
    ),
  ).toBe("html");
  expect(
    isPreviewableCode(
      "",
      '<!DOCTYPE   HTML><html lang="en"><body><svg></svg></body></html>',
    ),
  ).toBe("html");
  expect(
    isPreviewableCode(
      "xml",
      '<?xml version="1.0" encoding="UTF-8"?>\n<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"></svg>',
    ),
  ).toBe("svg");
  expect(
    isPreviewableCode(
      "plaintext",
      '<svg width="20" height="20"><rect width="20" height="20"/></svg>',
    ),
  ).toBe("svg");
  expect(
    isPreviewableCode("xml", "<html><body><p>XHTML-like</p></body></html>"),
  ).toBe("html");
});

test("isPreviewableCode rejects non-previewable languages, plain non-web xml, and empty blocks", () => {
  expect(isPreviewableCode("python", 'html = "<html><body>hi</body></html>"')).toBeNull();
  expect(isPreviewableCode("json", '{"html": "<svg></svg>"}')).toBeNull();
  expect(isPreviewableCode("typescript", "const s = '<!doctype html>';")).toBeNull();
  expect(isPreviewableCode("mermaid", "graph TD; A-->B;")).toBeNull();
  expect(isPreviewableCode("xml", "<config><flag>true</flag></config>")).toBeNull();
  expect(isPreviewableCode(undefined, "just some plain text")).toBeNull();
  expect(isPreviewableCode(undefined, "<svgicon />")).toBeNull();
  expect(isPreviewableCode(undefined, "<htmlx />")).toBeNull();
  expect(isPreviewableCode("html", "")).toBeNull();
  expect(isPreviewableCode("svg", "   \n\t  ")).toBeNull();
});

test("buildPreviewDocument passes HTML directly and wraps SVG in a centered responsive shell", () => {
  const html = "<!doctype html><html><body><h1>Hi</h1></body></html>";
  expect(buildPreviewDocument("html", html)).toBe(html);

  const svg =
    '<?xml version="1.0"?>\n<svg viewBox="0 0 100 100"><circle cx="50" cy="50" r="40"/></svg>';
  const wrapped = buildPreviewDocument("svg", svg);
  expect(wrapped).toContain("<!doctype html>");
  expect(wrapped).toContain("display: flex");
  expect(wrapped).toContain("align-items: center");
  expect(wrapped).toContain("justify-content: center");
  expect(wrapped).toContain("max-width: 100%");
  expect(wrapped).toContain(
    '<svg viewBox="0 0 100 100"><circle cx="50" cy="50" r="40"/></svg>',
  );
  expect(wrapped).not.toContain("<?xml");
});

test("extractCodeLanguage reads Streamdown language-* class names", () => {
  expect(extractCodeLanguage("language-html")).toBe("html");
  expect(extractCodeLanguage("foo language-svg bar")).toBe("svg");
  expect(extractCodeLanguage(undefined)).toBe("");
});
