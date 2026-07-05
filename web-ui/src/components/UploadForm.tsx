import { Loader2, Upload } from "lucide-react";
import { useCallback, useId, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { quoteValue } from "@/lib/filter";
import { UploadScansError, uploadScans } from "@/lib/upload";

export function UploadForm() {
  const fileInputId = useId();
  const fileRef = useRef<HTMLInputElement>(null);
  const [files, setFiles] = useState<File[]>([]);
  const [source, setSource] = useState("");
  const [categories, setCategories] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [fieldErrors, setFieldErrors] = useState<{
    files?: string;
    source?: string;
  }>({});

  const ready =
    files.length > 0 && source.trim().length > 0 && !submitting;

  const onFilesChange = useCallback(() => {
    const selected = fileRef.current?.files;
    setFiles(selected ? Array.from(selected) : []);
    setFieldErrors((prev) => ({ ...prev, files: undefined }));
  }, []);

  const validate = useCallback((): boolean => {
    const next: { files?: string; source?: string } = {};
    if (files.length === 0) {
      next.files = "Select at least one result file.";
    }
    if (!source.trim()) {
      next.source = "Source is mandatory.";
    }
    setFieldErrors(next);
    return Object.keys(next).length === 0;
  }, [files.length, source]);

  const onSubmit = useCallback(
    async (event: React.FormEvent) => {
      event.preventDefault();
      if (!validate()) {
        return;
      }
      setSubmitting(true);
      try {
        const { count } = await uploadScans({
          files,
          source,
          categories: categories.trim() || undefined,
        });
        const label =
          count === 1 ? "1 result uploaded" : `${count} results uploaded`;
        toast.success(label);
        if (files.length > count) {
          toast.message(
            `${files.length - count} file(s) could not be imported — check server logs.`,
          );
        }
        setFiles([]);
        if (fileRef.current) {
          fileRef.current.value = "";
        }
      } catch (err) {
        const message =
          err instanceof UploadScansError
            ? err.message
            : err instanceof Error
              ? err.message
              : "Upload failed.";
        toast.error(message);
      } finally {
        setSubmitting(false);
      }
    },
    [categories, files, source, validate],
  );

  const viewFilter = `source:${quoteValue(source.trim())}`;

  return (
    <form className="space-y-6" onSubmit={onSubmit} noValidate>
      <div className="space-y-2">
        <label
          htmlFor={fileInputId}
          className="text-sm font-medium leading-none"
        >
          Results
        </label>
        <input
          ref={fileRef}
          id={fileInputId}
          type="file"
          multiple
          accept=".xml,.json,.gz,.bz2,application/xml,application/json,application/gzip,application/x-bzip2"
          onChange={onFilesChange}
          disabled={submitting}
          aria-invalid={fieldErrors.files ? true : undefined}
          aria-describedby={`${fileInputId}-help`}
          className="block w-full text-sm file:mr-4 file:rounded-md file:border-0 file:bg-muted file:px-3 file:py-1.5 file:text-sm file:font-medium"
        />
        {fieldErrors.files ? (
          <p className="text-sm text-destructive" role="alert">
            {fieldErrors.files}
          </p>
        ) : null}
        {files.length > 0 ? (
          <ul className="list-inside list-disc text-sm text-muted-foreground">
            {files.map((f) => (
              <li key={`${f.name}-${f.size}-${f.lastModified}`}>{f.name}</li>
            ))}
          </ul>
        ) : null}
        <p id={`${fileInputId}-help`} className="text-sm text-muted-foreground">
          Nmap XML (<code className="text-xs">-oX</code>) or IVRE JSON (
          <code className="text-xs">ivre scancli --json</code>). Files may be
          compressed with gzip or bzip2.
        </p>
      </div>

      <div className="space-y-2">
        <label htmlFor={`${fileInputId}-categories`} className="text-sm font-medium">
          Categories
        </label>
        <Input
          id={`${fileInputId}-categories`}
          name="categories"
          placeholder="Comma-separated categories"
          value={categories}
          onChange={(e) => setCategories(e.target.value)}
          disabled={submitting}
          autoComplete="off"
        />
        <p className="text-sm text-muted-foreground">
          Optional tags for this scan, e.g.{" "}
          <code className="text-xs">Country-XX,Standard</code> or{" "}
          <code className="text-xs">AS-12345,Fast</code>.
        </p>
      </div>

      <div className="space-y-2">
        <label htmlFor={`${fileInputId}-source`} className="text-sm font-medium">
          Source <span className="text-destructive">*</span>
        </label>
        <Input
          id={`${fileInputId}-source`}
          name="source"
          placeholder="Source"
          value={source}
          onChange={(e) => {
            setSource(e.target.value);
            setFieldErrors((prev) => ({ ...prev, source: undefined }));
          }}
          disabled={submitting}
          required
          autoComplete="off"
          aria-invalid={fieldErrors.source ? true : undefined}
        />
        {fieldErrors.source ? (
          <p className="text-sm text-destructive" role="alert">
            {fieldErrors.source}
          </p>
        ) : null}
        <p className="text-sm text-muted-foreground">
          Where the scan was run from, e.g.{" "}
          <code className="text-xs">Provider-Scanner0</code> or{" "}
          <code className="text-xs">ISP-192.168.0.1</code>.
        </p>
      </div>

      <div className="flex flex-wrap items-center gap-3">
        <Button type="submit" disabled={!ready} className="gap-2">
          {submitting ? (
            <Loader2 className="size-4 animate-spin" aria-hidden />
          ) : (
            <Upload className="size-4" aria-hidden />
          )}
          Upload
        </Button>
        {source.trim() ? (
          <Button variant="outline" asChild>
            <Link to={`/view?q=${encodeURIComponent(viewFilter)}`}>
              Browse uploaded results
            </Link>
          </Button>
        ) : null}
      </div>
    </form>
  );
}
