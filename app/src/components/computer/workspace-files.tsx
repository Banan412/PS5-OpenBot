import { outcomeForPerson } from "@openbot/shared/approval-outcomes";
import {
  IconArrowUp,
  IconCode,
  IconDownload,
  IconEye,
  IconFile,
  IconFolder,
  IconRefresh,
  IconX,
} from "@tabler/icons-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { buildPreviewDocument, isPreviewableCode } from "@/lib/code-preview";
import { callComputer, type ToolOutcome } from "@/lib/computers/call";
import {
  onComputerViewRequest,
  takeRequestedFile,
} from "@/lib/computers/panel-view";
import { cn } from "@/lib/utils";

type WorkspaceEntry = {
  path: string;
  kind: "file" | "folder";
  bytes?: number;
};

type LoadedFile = {
  path: string;
  text: string;
  bytes?: number;
  truncated?: boolean;
};

function parentDirOf(path: string): string {
  const idx = path.lastIndexOf("/");
  return idx === -1 ? "" : path.slice(0, idx);
}

function baseNameOf(path: string): string {
  const idx = path.lastIndexOf("/");
  return idx === -1 ? path : path.slice(idx + 1);
}

function extensionOf(path: string): string {
  const name = baseNameOf(path);
  const dot = name.lastIndexOf(".");
  return dot === -1 ? "" : name.slice(dot + 1).toLowerCase();
}

function formatBytes(bytes: number | undefined): string {
  if (typeof bytes !== "number" || !Number.isFinite(bytes)) return "";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function mimeTypeForPath(path: string): string {
  switch (extensionOf(path)) {
    case "html":
    case "htm":
    case "xhtml":
      return "text/html;charset=utf-8";
    case "svg":
      return "image/svg+xml;charset=utf-8";
    case "json":
      return "application/json;charset=utf-8";
    case "css":
      return "text/css;charset=utf-8";
    case "csv":
      return "text/csv;charset=utf-8";
    case "md":
      return "text/markdown;charset=utf-8";
    default:
      return "text/plain;charset=utf-8";
  }
}

function parseEntries(raw: unknown): WorkspaceEntry[] {
  if (!Array.isArray(raw)) return [];
  const items: WorkspaceEntry[] = [];
  for (const item of raw) {
    if (!item || typeof item !== "object") continue;
    const path = (item as { path?: unknown }).path;
    const kind = (item as { kind?: unknown }).kind;
    const bytes = (item as { bytes?: unknown }).bytes;
    if (typeof path !== "string" || !path) continue;
    if (kind !== "file" && kind !== "folder") continue;
    items.push({
      path,
      kind,
      ...(typeof bytes === "number" ? { bytes } : {}),
    });
  }
  items.sort((a, b) => {
    if (a.kind !== b.kind) return a.kind === "folder" ? -1 : 1;
    return a.path.localeCompare(b.path);
  });
  return items;
}

function describeOutcomeProblem(
  outcome: ToolOutcome,
  fallback: string,
): string {
  if (outcome.starting === true) return "Starting the Bot's computer…";
  const reason = outcomeForPerson(String(outcome.reason ?? ""));
  return reason || fallback;
}

function triggerDownload(file: LoadedFile) {
  const blob = new Blob([file.text], { type: mimeTypeForPath(file.path) });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = baseNameOf(file.path) || "file.txt";
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

/**
 * Live explorer for files inside the Bot's workspace (`/files/list` and `/files/read`).
 * Supports directory navigation, raw text inspection, file download, and sandboxed HTML/SVG preview.
 */
export function WorkspaceFiles({ computerId }: { computerId: string }) {
  const [initialRequested] = useState(() => takeRequestedFile(computerId));
  const [currentDir, setCurrentDir] = useState(() =>
    initialRequested ? parentDirOf(initialRequested) : "",
  );
  const [entries, setEntries] = useState<WorkspaceEntry[]>([]);
  const [listTruncated, setListTruncated] = useState(false);
  const [loadingList, setLoadingList] = useState(true);
  const [listError, setListError] = useState<string | null>(null);

  const [selectedPath, setSelectedPath] = useState<string | null>(
    () => initialRequested ?? null,
  );
  const [loadedFile, setLoadedFile] = useState<LoadedFile | null>(null);
  const [loadingFile, setLoadingFile] = useState(false);
  const [fileError, setFileError] = useState<string | null>(null);
  const [viewMode, setViewMode] = useState<"preview" | "code">("preview");

  const listAbort = useRef<AbortController | null>(null);
  const fileAbort = useRef<AbortController | null>(null);

  const loadDirectory = useCallback(
    async (dir: string) => {
      listAbort.current?.abort();
      const controller = new AbortController();
      listAbort.current = controller;
      setLoadingList(true);
      setListError(null);
      const outcome = await callComputer(
        computerId,
        "/files/list",
        { method: "POST", body: dir ? { path: dir } : {} },
        controller.signal,
      );
      if (controller.signal.aborted) return;
      setLoadingList(false);
      if (outcome.ok !== true) {
        setEntries([]);
        setListTruncated(false);
        setListError(
          describeOutcomeProblem(outcome, "Could not list workspace files."),
        );
        return;
      }
      setEntries(parseEntries(outcome.entries));
      setListTruncated(outcome.truncated === true);
    },
    [computerId],
  );

  const openFile = useCallback(
    async (path: string) => {
      fileAbort.current?.abort();
      const controller = new AbortController();
      fileAbort.current = controller;
      setSelectedPath(path);
      setLoadingFile(true);
      setFileError(null);
      setViewMode("preview");
      const outcome = await callComputer(
        computerId,
        "/files/read",
        { method: "POST", body: { path } },
        controller.signal,
      );
      if (controller.signal.aborted) return;
      setLoadingFile(false);
      if (outcome.ok !== true) {
        setLoadedFile(null);
        setFileError(describeOutcomeProblem(outcome, "Could not read file."));
        return;
      }
      setLoadedFile({
        path: typeof outcome.path === "string" ? outcome.path : path,
        text: typeof outcome.text === "string" ? outcome.text : "",
        ...(typeof outcome.bytes === "number" ? { bytes: outcome.bytes } : {}),
        truncated: outcome.truncated === true,
      });
    },
    [computerId],
  );

  useEffect(() => {
    void loadDirectory(currentDir);
    return () => {
      listAbort.current?.abort();
    };
  }, [currentDir, loadDirectory]);

  useEffect(() => {
    if (!initialRequested) return;
    void openFile(initialRequested);
  }, [initialRequested, openFile]);

  useEffect(() => {
    return () => {
      fileAbort.current?.abort();
    };
  }, []);

  useEffect(() => {
    return onComputerViewRequest((request) => {
      if (request.computerId !== computerId || request.view !== "files") return;
      const requested = takeRequestedFile(computerId) ?? request.filePath;
      if (!requested) return;
      const nextDir = parentDirOf(requested);
      if (nextDir === currentDir) {
        void loadDirectory(nextDir);
      } else {
        setCurrentDir(nextDir);
      }
      void openFile(requested);
    });
  }, [computerId, currentDir, loadDirectory, openFile]);

  const previewKind = useMemo(
    () =>
      loadedFile
        ? isPreviewableCode(extensionOf(loadedFile.path), loadedFile.text)
        : null,
    [loadedFile],
  );

  const srcDoc = useMemo(
    () =>
      loadedFile && previewKind && viewMode === "preview"
        ? buildPreviewDocument(previewKind, loadedFile.text)
        : "",
    [loadedFile, previewKind, viewMode],
  );

  const segments = currentDir ? currentDir.split("/").filter(Boolean) : [];

  const handleRefresh = () => {
    void loadDirectory(currentDir);
    if (selectedPath) void openFile(selectedPath);
  };

  return (
    <div className="space-y-3" data-openbot-workspace-files="true">
      <div className="overflow-hidden rounded-2xl border dark:border-white/15">
        <div className="flex items-center justify-between gap-2 border-b bg-muted/30 px-3 py-2 text-xs">
          <nav
            aria-label="Workspace directory"
            className="flex min-w-0 flex-wrap items-center gap-1"
          >
            <button
              className={cn(
                "cursor-pointer rounded px-1 py-0.5 font-medium transition-colors hover:bg-accent",
                !currentDir ? "text-foreground" : "text-muted-foreground",
              )}
              onClick={() => setCurrentDir("")}
              type="button"
            >
              Workspace
            </button>
            {segments.map((segment, index) => {
              const path = segments.slice(0, index + 1).join("/");
              const isLast = index === segments.length - 1;
              return (
                <span className="flex items-center gap-1" key={path}>
                  <span aria-hidden className="text-muted-foreground">
                    /
                  </span>
                  <button
                    className={cn(
                      "cursor-pointer truncate rounded px-1 py-0.5 transition-colors hover:bg-accent",
                      isLast
                        ? "font-medium text-foreground"
                        : "text-muted-foreground",
                    )}
                    onClick={() => setCurrentDir(path)}
                    type="button"
                  >
                    {segment}
                  </button>
                </span>
              );
            })}
          </nav>
          <div className="flex shrink-0 items-center gap-1">
            {currentDir ? (
              <button
                aria-label="Up one folder"
                className="cursor-pointer rounded p-1 text-muted-foreground transition-colors hover:bg-accent hover:text-foreground"
                onClick={() => setCurrentDir(parentDirOf(currentDir))}
                title="Up one folder"
                type="button"
              >
                <IconArrowUp size={14} />
              </button>
            ) : null}
            <button
              aria-label="Refresh files"
              className="cursor-pointer rounded p-1 text-muted-foreground transition-colors hover:bg-accent hover:text-foreground"
              onClick={handleRefresh}
              title="Refresh"
              type="button"
            >
              <IconRefresh size={14} />
            </button>
          </div>
        </div>

        {loadingList ? (
          <div className="px-3 py-6 text-center text-muted-foreground text-xs">
            Loading workspace files…
          </div>
        ) : listError ? (
          <div className="flex flex-col items-center gap-2 px-3 py-6 text-center text-muted-foreground text-xs">
            <span>{listError}</span>
            <button
              className="cursor-pointer underline"
              onClick={handleRefresh}
              type="button"
            >
              Retry
            </button>
          </div>
        ) : entries.length === 0 ? (
          <div className="px-3 py-6 text-center text-muted-foreground text-xs">
            No files saved in this folder yet.
          </div>
        ) : (
          <ul className="max-h-48 divide-y overflow-y-auto text-xs">
            {entries.map((entry) => {
              const name = baseNameOf(entry.path);
              const isSelected =
                entry.kind === "file" && selectedPath === entry.path;
              return (
                <li key={entry.path}>
                  <button
                    className={cn(
                      "flex w-full cursor-pointer items-center justify-between gap-2 px-3 py-2 text-left transition-colors hover:bg-accent/60",
                      isSelected && "bg-accent font-medium",
                    )}
                    onClick={() => {
                      if (entry.kind === "folder") {
                        setCurrentDir(entry.path);
                      } else {
                        void openFile(entry.path);
                      }
                    }}
                    type="button"
                  >
                    <span className="flex min-w-0 items-center gap-2">
                      {entry.kind === "folder" ? (
                        <IconFolder
                          className="shrink-0 text-muted-foreground"
                          size={15}
                        />
                      ) : (
                        <IconFile
                          className="shrink-0 text-muted-foreground"
                          size={15}
                        />
                      )}
                      <span className="truncate">{name}</span>
                    </span>
                    {entry.kind === "file" && entry.bytes !== undefined ? (
                      <span className="shrink-0 text-[11px] text-muted-foreground tabular-nums">
                        {formatBytes(entry.bytes)}
                      </span>
                    ) : null}
                  </button>
                </li>
              );
            })}
          </ul>
        )}
        {listTruncated ? (
          <div className="border-t bg-muted/20 px-3 py-1.5 text-[11px] text-muted-foreground">
            Showing the first items in this folder.
          </div>
        ) : null}
      </div>

      {selectedPath ? (
        <div
          className="overflow-hidden rounded-2xl border dark:border-white/15"
          data-openbot-workspace-file-viewer={selectedPath}
        >
          <div className="flex flex-wrap items-center justify-between gap-2 border-b bg-muted/30 px-3 py-2 text-xs">
            <div className="flex min-w-0 items-center gap-1.5">
              <span className="truncate font-medium" title={selectedPath}>
                {selectedPath}
              </span>
              {loadedFile?.bytes !== undefined ? (
                <span className="shrink-0 text-[11px] text-muted-foreground tabular-nums">
                  ({formatBytes(loadedFile.bytes)})
                </span>
              ) : null}
            </div>
            <div className="flex shrink-0 items-center gap-1.5">
              {loadedFile && previewKind ? (
                <fieldset
                  aria-label="Workspace file view"
                  className="m-0 inline-flex items-center rounded border-0 bg-muted/70 p-0.5 text-[11px]"
                >
                  <button
                    aria-pressed={viewMode === "preview"}
                    className={cn(
                      "inline-flex cursor-pointer items-center gap-1 rounded-sm px-1.5 py-0.5 font-medium transition-colors",
                      viewMode === "preview"
                        ? "bg-background text-foreground shadow-xs"
                        : "text-muted-foreground hover:text-foreground",
                    )}
                    onClick={() => setViewMode("preview")}
                    type="button"
                  >
                    <IconEye aria-hidden size={12} />
                    <span>Preview</span>
                  </button>
                  <button
                    aria-pressed={viewMode === "code"}
                    className={cn(
                      "inline-flex cursor-pointer items-center gap-1 rounded-sm px-1.5 py-0.5 font-medium transition-colors",
                      viewMode === "code"
                        ? "bg-background text-foreground shadow-xs"
                        : "text-muted-foreground hover:text-foreground",
                    )}
                    onClick={() => setViewMode("code")}
                    type="button"
                  >
                    <IconCode aria-hidden size={12} />
                    <span>Code</span>
                  </button>
                </fieldset>
              ) : null}
              {loadedFile ? (
                <button
                  aria-label={`Download ${baseNameOf(loadedFile.path)}`}
                  className="inline-flex cursor-pointer items-center gap-1 rounded px-1.5 py-1 text-[11px] text-muted-foreground transition-colors hover:bg-accent hover:text-foreground"
                  onClick={() => triggerDownload(loadedFile)}
                  title="Download file"
                  type="button"
                >
                  <IconDownload size={13} />
                  <span>Download</span>
                </button>
              ) : null}
              <button
                aria-label="Close file viewer"
                className="cursor-pointer rounded p-1 text-muted-foreground transition-colors hover:bg-accent hover:text-foreground"
                onClick={() => {
                  fileAbort.current?.abort();
                  setSelectedPath(null);
                  setLoadedFile(null);
                  setFileError(null);
                }}
                title="Close"
                type="button"
              >
                <IconX size={14} />
              </button>
            </div>
          </div>

          {loadingFile ? (
            <div className="px-3 py-6 text-center text-muted-foreground text-xs">
              Reading file…
            </div>
          ) : fileError ? (
            <div className="flex flex-col items-center gap-2 px-3 py-6 text-center text-muted-foreground text-xs">
              <span>{fileError}</span>
              <button
                className="cursor-pointer underline"
                onClick={() => void openFile(selectedPath)}
                type="button"
              >
                Retry
              </button>
            </div>
          ) : loadedFile ? (
            <>
              {previewKind && viewMode === "preview" ? (
                <div className="bg-white">
                  {/* CRITICAL: never add allow-same-origin so untrusted AI HTML/SVG cannot access session cookies, localStorage, or OpenBot APIs. */}
                  <iframe
                    className="block h-[320px] w-full border-0 bg-white"
                    referrerPolicy="no-referrer"
                    sandbox="allow-scripts"
                    srcDoc={srcDoc}
                    title={
                      previewKind === "svg" ? "SVG preview" : "HTML preview"
                    }
                  />
                </div>
              ) : (
                <pre className="max-h-80 overflow-auto p-3 font-mono text-xs leading-relaxed whitespace-pre-wrap break-words">
                  <code>{loadedFile.text}</code>
                </pre>
              )}
              {loadedFile.truncated ? (
                <div className="border-t bg-muted/20 px-3 py-1.5 text-[11px] text-muted-foreground">
                  File preview was truncated to the read limit.
                </div>
              ) : null}
            </>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}
