import { ApiError } from "@/lib/api";
import { formatQueryError } from "@/lib/format";

export function ReportStatus({
  loading,
  error,
  empty,
}: {
  loading?: boolean;
  error?: Error | null;
  empty?: string;
}) {
  if (loading)
    return (
      <p role="status" className="py-10 text-muted-foreground">
        Loading observations…
      </p>
    );
  if (error) {
    const denied =
      error instanceof ApiError && [401, 403].includes(error.status);
    const unavailable =
      error instanceof ApiError && [404, 501].includes(error.status);
    return (
      <div
        role="alert"
        className="my-6 border-l-2 border-destructive bg-destructive/5 p-4 text-sm"
      >
        <p className="font-semibold">
          {denied
            ? "Access denied"
            : unavailable
              ? "Source unavailable"
              : "Unable to load observations"}
        </p>
        <p className="mt-1 break-words">
          {denied
            ? "You do not have permission to read this source."
            : unavailable
              ? "This source is not exposed or supported by the server."
              : formatQueryError(error)}
        </p>
      </div>
    );
  }
  return empty ? <p className="py-10 text-muted-foreground">{empty}</p> : null;
}
