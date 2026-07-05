import { Upload } from "lucide-react";

import { UploadForm } from "@/components/UploadForm";
import { isModuleEnabled, isUploadOk } from "@/lib/config";

/**
 * Scan-result upload route. Operator tool (not a data section):
 * reachable from the header when ``WEB_UPLOAD_OK`` is enabled
 * and the ``view`` module is exposed.
 * Posts to ``POST /cgi/view``; the server audit-logs successful
 * imports as ``event_type: "upload"`` when an audit backend is
 * configured. No client-side audit call is required.
 */
export function UploadRoute() {
  if (!isUploadOk()) {
    return <UploadDisabledGate />;
  }

  if (!isModuleEnabled("view")) {
    return <UploadModuleGate />;
  }

  return (
    <div className="mx-auto w-full max-w-2xl space-y-6 px-6 py-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">
          Upload scan results
        </h1>
        <p className="text-sm text-muted-foreground">
          Import Nmap XML or IVRE JSON files into the active scan database
          and the merged view. Successful uploads are recorded in the audit
          log when auditing is enabled on this server.
        </p>
      </div>
      <UploadForm />
    </div>
  );
}

function UploadDisabledGate() {
  return (
    <div className="mx-auto flex max-w-screen-md flex-col items-center justify-center gap-4 px-4 py-24 text-center">
      <Upload className="size-16 text-muted-foreground" aria-hidden />
      <h2 className="text-2xl font-semibold tracking-tight">
        Uploads are disabled
      </h2>
      <p className="text-muted-foreground">
        This instance does not authorize uploads{" "}
        <span className="text-muted-foreground/80">(this is the default)</span>.
        {" "}
        To enable them, set{" "}
        <code className="rounded bg-muted px-1.5 py-0.5 text-sm">
          WEB_UPLOAD_OK = True
        </code>{" "}
        in{" "}
        <code className="rounded bg-muted px-1.5 py-0.5 text-sm">ivre.conf</code>.
      </p>
    </div>
  );
}

function UploadModuleGate() {
  return (
    <div className="mx-auto flex max-w-screen-md flex-col items-center justify-center gap-4 px-4 py-24 text-center">
      <Upload className="size-16 text-muted-foreground" aria-hidden />
      <h2 className="text-2xl font-semibold tracking-tight">
        Upload not available
      </h2>
      <p className="text-muted-foreground">
        The view module is not exposed on this server, so scan uploads are
        disabled. Check <code className="text-xs">WEB_MODULES</code> and your
        database configuration.
      </p>
    </div>
  );
}
