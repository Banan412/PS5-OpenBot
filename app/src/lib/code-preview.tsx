import {
  IconArrowsMaximize,
  IconArrowsMinimize,
  IconCode,
  IconEye,
} from "@tabler/icons-react";
import { isValidElement, useContext, useMemo, useState } from "react";
import {
  CodeBlock,
  CodeBlockContainer,
  CodeBlockCopyButton,
  CodeBlockDownloadButton,
  CodeBlockHeader,
  type ControlsConfig,
  StreamdownContext,
  useIsCodeFenceIncomplete,
} from "streamdown";
import { cn } from "@/lib/utils";

export type PreviewKind = "html" | "svg";

const HTML_FENCE_LANGUAGES = new Set(["html", "htm", "xhtml"]);
const CONTENT_DETECT_LANGUAGES = new Set([
  "",
  "xml",
  "text",
  "plaintext",
  "txt",
]);

const LANGUAGE_CLASS_RE = /language-([^\s]+)/;
const START_LINE_RE = /startLine=(\d+)/;
const NO_LINE_NUMBERS_RE = /\bnoLineNumbers\b/;
const HTML_DOC_RE = /(?:<!doctype\s+html\b|<html\b)/i;
const SVG_TAG_RE = /<svg\b/i;
const XML_PROLOG_RE = /^\s*<\?xml[\s\S]*?\?>\s*/i;

/**
 * Determine whether a fenced code block can be previewed inline as HTML or SVG.
 *
 * Matches explicit `html` / `htm` / `xhtml` and `svg` blocks, as well as `xml`
 * or untagged plain blocks whose content begins/contains `<svg` or
 * `<!doctype html>` / `<html>`.
 */
export function isPreviewableCode(
  language: string | undefined,
  code: string,
): PreviewKind | null {
  const trimmed = code.trim();
  if (!trimmed) return null;

  const normalized = language?.trim().toLowerCase() ?? "";
  if (normalized === "svg") return "svg";
  if (HTML_FENCE_LANGUAGES.has(normalized)) return "html";
  if (!CONTENT_DETECT_LANGUAGES.has(normalized)) return null;

  if (HTML_DOC_RE.test(trimmed)) return "html";
  if (SVG_TAG_RE.test(trimmed)) return "svg";
  return null;
}

/**
 * Build the `srcDoc` HTML string for a sandboxed preview iframe.
 *
 * HTML blocks are passed directly; SVG blocks are wrapped in a centered,
 * responsive HTML5 shell.
 */
export function buildPreviewDocument(kind: PreviewKind, code: string): string {
  if (kind === "html") return code;

  const svgMarkup = code.replace(XML_PROLOG_RE, "").trim();
  return [
    "<!doctype html>",
    '<html lang="en">',
    "<head>",
    '<meta charset="utf-8" />',
    '<meta name="viewport" content="width=device-width, initial-scale=1" />',
    "<style>",
    "*, *::before, *::after { box-sizing: border-box; }",
    "html, body {",
    "  margin: 0;",
    "  padding: 0;",
    "  width: 100%;",
    "  min-height: 100%;",
    "  background: #ffffff;",
    "  color: #111827;",
    "  display: flex;",
    "  align-items: center;",
    "  justify-content: center;",
    "}",
    "body { padding: 16px; overflow: auto; }",
    "svg { max-width: 100%; max-height: calc(100vh - 32px); height: auto; display: block; }",
    "</style>",
    "</head>",
    "<body>",
    svgMarkup,
    "</body>",
    "</html>",
  ].join("\n");
}

export function extractCodeLanguage(className: string | undefined): string {
  return className?.match(LANGUAGE_CLASS_RE)?.at(1) ?? "";
}

export function extractCodeText(children: unknown): string {
  if (typeof children === "string") return children;
  if (Array.isArray(children)) return children.map(extractCodeText).join("");
  if (isValidElement(children)) {
    const props = children.props as { children?: unknown } | null;
    if (props && "children" in props) {
      return extractCodeText(props.children);
    }
  }
  return "";
}

function isCodeControlEnabled(
  controls: ControlsConfig,
  button: "copy" | "download",
): boolean {
  if (typeof controls === "boolean") return controls;
  const codeControls = controls.code;
  if (codeControls === false) return false;
  if (codeControls === true || codeControls === undefined) return true;
  return codeControls[button] !== false;
}

export function PreviewableCodeBlock({
  className,
  code,
  language,
  metastring,
  previewKind,
}: {
  className?: string;
  code: string;
  language: string;
  metastring?: string;
  previewKind: PreviewKind;
}) {
  const { controls, lineNumbers } = useContext(StreamdownContext);
  const isIncomplete = useIsCodeFenceIncomplete();
  const [view, setView] = useState<"code" | "preview">("code");
  const [expanded, setExpanded] = useState(false);

  const effectiveLanguage = language.trim().toLowerCase() || previewKind;
  const startLineMatch = metastring?.match(START_LINE_RE);
  const parsedStartLine = startLineMatch
    ? Number.parseInt(startLineMatch[1], 10)
    : undefined;
  const startLine =
    parsedStartLine !== undefined && parsedStartLine >= 1
      ? parsedStartLine
      : undefined;
  const showLineNumbers =
    !(metastring ? NO_LINE_NUMBERS_RE.test(metastring) : false) &&
    lineNumbers !== false;

  const showDownload = isCodeControlEnabled(controls, "download");
  const showCopy = isCodeControlEnabled(controls, "copy");
  const showingPreview = view === "preview" && !isIncomplete;

  const srcDoc = useMemo(
    () => (showingPreview ? buildPreviewDocument(previewKind, code) : ""),
    [showingPreview, previewKind, code],
  );

  const actions = (
    <>
      {isIncomplete ? (
        <span
          className="inline-flex items-center gap-1 px-1 text-[11px] text-muted-foreground"
          data-openbot-preview-streaming="true"
        >
          <span
            aria-hidden="true"
            className="size-1.5 animate-pulse rounded-full bg-amber-500"
          />
          Streaming…
        </span>
      ) : null}
      <fieldset
        aria-label="Code block view"
        className="m-0 inline-flex items-center rounded border-0 bg-muted/70 p-0.5 text-[11px]"
      >
        <button
          aria-pressed={showingPreview}
          className={cn(
            "inline-flex cursor-pointer items-center gap-1 rounded-sm px-1.5 py-0.5 font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-50",
            showingPreview
              ? "bg-background text-foreground shadow-xs"
              : "text-muted-foreground hover:text-foreground",
          )}
          data-openbot-preview-toggle="preview"
          disabled={isIncomplete}
          onClick={() => setView("preview")}
          title={
            isIncomplete
              ? "Preview available once streaming completes"
              : `Preview ${previewKind.toUpperCase()}`
          }
          type="button"
        >
          <IconEye aria-hidden="true" size={12} />
          <span>Preview</span>
        </button>
        <button
          aria-pressed={!showingPreview}
          className={cn(
            "inline-flex cursor-pointer items-center gap-1 rounded-sm px-1.5 py-0.5 font-medium transition-colors",
            !showingPreview
              ? "bg-background text-foreground shadow-xs"
              : "text-muted-foreground hover:text-foreground",
          )}
          data-openbot-preview-toggle="code"
          onClick={() => setView("code")}
          title="View source code"
          type="button"
        >
          <IconCode aria-hidden="true" size={12} />
          <span>Code</span>
        </button>
      </fieldset>
      {showingPreview ? (
        <button
          aria-label={
            expanded ? "Collapse preview height" : "Expand preview height"
          }
          aria-pressed={expanded}
          className="cursor-pointer p-1 text-muted-foreground transition-all hover:text-foreground"
          data-openbot-preview-expand="true"
          onClick={() => setExpanded((current) => !current)}
          title={expanded ? "Compact height" : "Expand height"}
          type="button"
        >
          {expanded ? (
            <IconArrowsMinimize aria-hidden="true" size={14} />
          ) : (
            <IconArrowsMaximize aria-hidden="true" size={14} />
          )}
        </button>
      ) : null}
      {showDownload ? (
        <CodeBlockDownloadButton code={code} language={effectiveLanguage} />
      ) : null}
      {showCopy ? <CodeBlockCopyButton code={code} /> : null}
    </>
  );

  if (showingPreview) {
    return (
      <CodeBlockContainer
        dir="ltr"
        isIncomplete={isIncomplete}
        language={effectiveLanguage}
      >
        <CodeBlockHeader language={effectiveLanguage} />
        <div className="pointer-events-none sticky top-2 z-10 -mt-10 flex h-8 items-center justify-end">
          <div
            className="pointer-events-auto flex shrink-0 items-center gap-2 rounded-md border border-sidebar bg-sidebar/80 px-1.5 py-1 supports-[backdrop-filter]:bg-sidebar/70 supports-[backdrop-filter]:backdrop-blur"
            data-streamdown="code-block-actions"
          >
            {actions}
          </div>
        </div>
        <div
          className="overflow-hidden rounded-md border border-border bg-white"
          data-openbot-code-preview={previewKind}
        >
          {/* CRITICAL: never add allow-same-origin so untrusted AI HTML/JS cannot access session cookies, localStorage, or OpenBot APIs. */}
          <iframe
            className={cn(
              "block w-full border-0 bg-white transition-[height] duration-150",
              expanded ? "h-[560px]" : "h-[360px]",
            )}
            referrerPolicy="no-referrer"
            sandbox="allow-scripts"
            srcDoc={srcDoc}
            title={previewKind === "svg" ? "SVG preview" : "HTML preview"}
          />
        </div>
      </CodeBlockContainer>
    );
  }

  return (
    <CodeBlock
      className={className}
      code={code}
      isIncomplete={isIncomplete}
      language={effectiveLanguage}
      lineNumbers={showLineNumbers}
      startLine={startLine}
    >
      {actions}
    </CodeBlock>
  );
}
