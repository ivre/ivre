/**
 * Scan-result upload against ``POST /cgi/view``.
 *
 * Mirrors the legacy ``upload.html`` form: multipart fields
 * ``result`` (one or more files), ``source`` (mandatory),
 * ``categories`` (optional, comma-separated) and ``referer``.
 * The server ingests via ``db.nmap.store_scan`` and merges into
 * ``db.view``; a successful write is audit-logged server-side as
 * ``event_type: "upload"`` when an audit backend is configured.
 *
 * Same-origin ``fetch`` sends a same-origin ``Referer`` header (satisfying ``@check_referer``);
 * ``credentials: "same-origin"`` carries the session cookie.
 * Do **not** set ``Content-Type`` — the browser must supply the
 * multipart boundary.
 */

import { CGI_ROOT } from "@/lib/api";

export interface UploadScansParams {
  files: File[];
  source: string;
  /** Comma-separated category tags; forwarded verbatim to the server. */
  categories?: string;
  /** Defaults to ``window.location.href`` when omitted. */
  referer?: string;
}

export interface UploadScansResult {
  count: number;
}

export class UploadScansError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = "UploadScansError";
    this.status = status;
  }
}

async function readErrorMessage(response: Response): Promise<string> {
  const contentType = response.headers.get("Content-Type") ?? "";
  if (contentType.includes("application/json")) {
    try {
      const body = (await response.json()) as { error?: string };
      if (typeof body.error === "string" && body.error.length > 0) {
        return body.error;
      }
    } catch {
      // fall through to status text
    }
  }
  try {
    const text = (await response.text()).trim();
    if (text.length > 0) {
      return text;
    }
  } catch {
    // ignore
  }
  return `${response.status} ${response.statusText}`;
}

/** POST scan files to ``/cgi/view``. Returns the number of results
 *  the backend successfully ingested (may be lower than the number
 *  of files submitted when individual imports fail). */
export async function uploadScans(
  params: UploadScansParams,
  signal?: AbortSignal,
): Promise<UploadScansResult> {
  const { files, source, categories, referer } = params;
  if (files.length === 0) {
    throw new UploadScansError(0, "At least one result file is required.");
  }
  const trimmedSource = source.trim();
  if (!trimmedSource) {
    throw new UploadScansError(0, "Source is mandatory.");
  }

  const form = new FormData();
  for (const file of files) {
    form.append("result", file);
  }
  form.append("source", trimmedSource);
  if (categories !== undefined && categories.trim() !== "") {
    form.append("categories", categories.trim());
  }
  form.append(
    "referer",
    referer ?? (typeof window !== "undefined" ? window.location.href : ""),
  );

  const url = `${CGI_ROOT}/view`;
  const response = await fetch(url, {
    method: "POST",
    credentials: "same-origin",
    body: form,
    signal,
  });

  if (!response.ok) {
    const message = await readErrorMessage(response);
    throw new UploadScansError(response.status, message);
  }

  const body = (await response.json()) as { count?: unknown };
  const count = body.count;
  if (typeof count !== "number" || !Number.isFinite(count)) {
    throw new UploadScansError(
      response.status,
      "Upload succeeded but the server returned an unexpected response.",
    );
  }
  return { count };
}
