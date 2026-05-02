import { ChevronLeft, ChevronRight } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import type { HostRecord } from "@/lib/api";
import {
  formatPort,
  formatTimestamp,
  getCountryFlag,
  getPortColor,
  getTagColor,
} from "@/lib/format";
import { cn } from "@/lib/utils";

export interface HostDetailSheetProps {
  host: HostRecord | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onPrev?: () => void;
  onNext?: () => void;
  hasPrev?: boolean;
  hasNext?: boolean;
}

/**
 * Right-side slide-over with the full detail of a single host.
 *
 * Built on shadcn ``<Sheet>`` so we get free keyboard handling
 * (Esc-to-close), focus trap, and ARIA wiring. The prev/next
 * buttons walk the surrounding result list, mirroring the
 * prototype's host-detail panel.
 */
export function HostDetailSheet({
  host,
  open,
  onOpenChange,
  onPrev,
  onNext,
  hasPrev,
  hasNext,
}: HostDetailSheetProps) {
  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent
        side="right"
        className="flex w-full flex-col gap-0 overflow-hidden p-0 sm:max-w-3xl"
      >
        {host ? (
          <>
            <SheetHeader className="border-b border-border p-4">
              {/*
                ``pr-10`` reserves 2.5 rem of right space for shadcn's
                close (``X``) button, which is rendered by
                ``<SheetContent>`` itself at ``absolute top-4
                right-4``. Without this, our prev/next icon buttons
                sit on top of the X.
              */}
              <div className="flex items-center justify-between gap-4 pr-10">
                <SheetTitle className="font-mono text-xl">
                  {host.addr}
                </SheetTitle>
                <div className="flex items-center gap-1">
                  <Button
                    variant="ghost"
                    size="icon"
                    aria-label="Previous host"
                    onClick={() => onPrev?.()}
                    disabled={!hasPrev}
                  >
                    <ChevronLeft className="size-4" />
                  </Button>
                  <Button
                    variant="ghost"
                    size="icon"
                    aria-label="Next host"
                    onClick={() => onNext?.()}
                    disabled={!hasNext}
                  >
                    <ChevronRight className="size-4" />
                  </Button>
                </div>
              </div>
              <SheetDescription className="sr-only">
                Detailed information for host {host.addr}.
              </SheetDescription>
            </SheetHeader>

            <div className="flex-1 overflow-y-auto p-4 text-sm">
              <HostDetailBody host={host} />
            </div>
          </>
        ) : null}
      </SheetContent>
    </Sheet>
  );
}

function HostDetailBody({ host }: { host: HostRecord }) {
  return (
    <div className="space-y-6">
      <Section title="Network">
        <KV label="Country">
          {host.infos?.country_code ? (
            <>
              <span aria-hidden>
                {getCountryFlag(host.infos.country_code)}{" "}
              </span>
              {host.infos.country_name ?? host.infos.country_code}
            </>
          ) : (
            "—"
          )}
        </KV>
        <KV label="AS">
          {host.infos?.as_num
            ? `AS${host.infos.as_num}${
                host.infos.as_name ? ` (${host.infos.as_name})` : ""
              }`
            : "—"}
        </KV>
        <KV label="Source">{(host.source ?? []).join(", ") || "—"}</KV>
        <KV label="First seen">{formatTimestamp(host.starttime) || "—"}</KV>
        <KV label="Last seen">{formatTimestamp(host.endtime) || "—"}</KV>
      </Section>

      {host.hostnames && host.hostnames.length > 0 ? (
        <Section title="Hostnames">
          <ul className="space-y-1 font-mono text-xs">
            {host.hostnames.map((h) => (
              <li key={h.name}>
                {h.name}
                {h.type ? (
                  <span className="ml-2 text-muted-foreground">({h.type})</span>
                ) : null}
              </li>
            ))}
          </ul>
        </Section>
      ) : null}

      {host.tags && host.tags.length > 0 ? (
        <Section title="Tags">
          <div className="flex flex-wrap gap-1.5">
            {host.tags.map((tag) => (
              <Badge
                key={tag.value}
                className={cn("border-none", getTagColor(tag.type))}
                title={tag.info?.join("\n")}
              >
                {tag.value}
              </Badge>
            ))}
          </div>
        </Section>
      ) : null}

      {host.categories && host.categories.length > 0 ? (
        <Section title="Categories">
          <div className="flex flex-wrap gap-1.5">
            {host.categories.map((cat) => (
              <Badge key={cat} variant="outline">
                {cat}
              </Badge>
            ))}
          </div>
        </Section>
      ) : null}

      {host.ports && host.ports.length > 0 ? (
        <Section title="Ports & services">
          <ul className="space-y-3">
            {host.ports
              .filter((p) => typeof p.port === "number")
              .map((p) => (
                <li key={`p-${p.protocol}-${p.port}`} className="space-y-1">
                  <div className="flex items-center gap-2">
                    <Badge
                      className={cn(
                        "border-none font-mono",
                        getPortColor(p.state_state),
                      )}
                    >
                      {formatPort(p)}
                    </Badge>
                    <span className="text-xs text-muted-foreground">
                      {p.state_state ?? "—"}
                    </span>
                    {p.service_name ? (
                      <span className="text-xs">
                        <span className="font-semibold">{p.service_name}</span>
                        {p.service_product
                          ? ` (${p.service_product}${
                              p.service_version ? ` ${p.service_version}` : ""
                            })`
                          : null}
                      </span>
                    ) : null}
                  </div>
                  {p.scripts && p.scripts.length > 0 ? (
                    <ul className="space-y-1 pl-4 text-xs">
                      {p.scripts.map((script) => (
                        <li key={script.id}>
                          {/*
                            Open by default — Nmap script output is the
                            highest-value content on the detail page,
                            so make the user click to *hide* rather
                            than to *reveal*.
                          */}
                          <details open>
                            <summary className="cursor-pointer font-mono text-muted-foreground hover:text-foreground">
                              {script.id}
                            </summary>
                            {script.output ? (
                              <pre className="mt-1 whitespace-pre-wrap rounded bg-muted/40 p-2 font-mono text-xs">
                                {script.output}
                              </pre>
                            ) : null}
                          </details>
                        </li>
                      ))}
                    </ul>
                  ) : null}
                </li>
              ))}
          </ul>
        </Section>
      ) : null}
    </div>
  );
}

function Section({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <section>
      <h3 className="mb-2 text-sm font-semibold uppercase tracking-wide text-muted-foreground">
        {title}
      </h3>
      {children}
    </section>
  );
}

function KV({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex gap-2">
      <span className="w-24 shrink-0 text-xs font-semibold text-muted-foreground">
        {label}
      </span>
      <span className="text-sm">{children}</span>
    </div>
  );
}
