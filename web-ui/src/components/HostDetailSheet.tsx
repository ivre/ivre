import {
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  ChevronUp,
  Link as LinkIcon,
} from "lucide-react";
import { useMemo, useState } from "react";
import { toast } from "sonner";

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
import type { Filter, HighlightMap } from "@/lib/filter";
import {
  formatPort,
  formatTimestamp,
  getCountryFlag,
  getPortColor,
  getTagColor,
  sortTagsByImportance,
} from "@/lib/format";
import { cn } from "@/lib/utils";

/** Cap on the number of tag chips rendered in the collapsed
 *  "Tags" section of the detail sheet. Larger than the host card
 *  cap because the detail sheet is the place users go to inspect
 *  everything, but still bounded so a 500-tag host doesn't paint
 *  a wall of chips on open. */
const TAGS_COLLAPSED_LIMIT = 30;

export interface HostDetailSheetProps {
  host: HostRecord | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onPrev?: () => void;
  onNext?: () => void;
  hasPrev?: boolean;
  hasNext?: boolean;
  /** Click-to-add-filter callback. Mirrors the chip behaviour on
   *  ``HostCard``: clicking on the country, AS, source, hostname,
   *  category, tag, port, service, or product chip emits a
   *  ``Filter`` to be appended to the active query. */
  onAddFilter?: (filter: Filter) => void;
  /** Highlight map used to surface chips that correspond to active
   *  filters (yellow in light, soft orange in dark). Same payload
   *  the surrounding ``HostCard`` consumes. */
  highlights?: HighlightMap;
}

/** Copy the current page URL to the clipboard, falling back to a
 *  prompt-style toast when the clipboard API is unavailable
 *  (insecure context, missing permission, etc.). */
async function copyPermalink(): Promise<void> {
  const url = window.location.href;
  try {
    if (
      typeof navigator !== "undefined" &&
      navigator.clipboard &&
      typeof navigator.clipboard.writeText === "function"
    ) {
      await navigator.clipboard.writeText(url);
      toast.success("Permalink copied to clipboard");
      return;
    }
  } catch {
    // fall through to the manual-copy toast below
  }
  toast.message("Permalink", { description: url });
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
  onAddFilter,
  highlights,
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
                    aria-label="Copy permalink"
                    onClick={() => copyPermalink()}
                  >
                    <LinkIcon className="size-4" />
                  </Button>
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
              <HostDetailBody
                host={host}
                onAddFilter={onAddFilter}
                highlights={highlights}
              />
            </div>
          </>
        ) : null}
      </SheetContent>
    </Sheet>
  );
}

function HostDetailBody({
  host,
  onAddFilter,
  highlights,
}: {
  host: HostRecord;
  onAddFilter?: (filter: Filter) => void;
  highlights?: HighlightMap;
}) {
  const country = host.infos?.country_code;
  const asNum = host.infos?.as_num;
  // ``source`` is a single string on active scan documents
  // and an array on view records — see ``HostRecord``. Coerce
  // here rather than crashing in ``sources.map()`` below.
  const sources: string[] = Array.isArray(host.source)
    ? host.source
    : host.source
      ? [host.source]
      : [];
  const countryHL = highlights?.get("country");
  const asnumHL = highlights?.get("asnum");
  const sourceHL = highlights?.get("source");
  const hostnameHL = highlights?.get("hostname");
  const tagHL = highlights?.get("tag");
  const categoryHL = highlights?.get("category");
  const portHL = highlights?.get("port");
  const serviceHL = highlights?.get("service");
  const productHL = highlights?.get("product");

  // Sort + slice tags to keep the "Tags" section from painting a
  // wall of hundreds of chips on bulk-tagged hosts. Mirrors the
  // behaviour on ``HostCard`` (see ``TAGS_COLLAPSED_LIMIT`` there)
  // with a looser cap because the detail sheet is the inspection
  // surface. Highlighted tags (those matching an active tag filter)
  // sort to the head of the list so they always stay visible when
  // collapsed.
  const [tagsExpanded, setTagsExpanded] = useState(false);
  const sortedTags = useMemo(
    () =>
      sortTagsByImportance(
        host.tags ?? [],
        tagHL ? (t) => tagHL.has(t.value.toLowerCase()) : undefined,
      ),
    [host.tags, tagHL],
  );
  const hasTagOverflow = sortedTags.length > TAGS_COLLAPSED_LIMIT;
  const hiddenTagCount = hasTagOverflow
    ? sortedTags.length - TAGS_COLLAPSED_LIMIT
    : 0;
  const visibleTags = useMemo(
    () =>
      tagsExpanded || !hasTagOverflow
        ? sortedTags
        : sortedTags.slice(0, TAGS_COLLAPSED_LIMIT),
    [sortedTags, tagsExpanded, hasTagOverflow],
  );

  return (
    <div className="space-y-6">
      <Section title="Network">
        <KV label="Country">
          {country ? (
            <FilterChipText
              highlighted={countryHL?.has(country.toLowerCase())}
              onClick={() =>
                onAddFilter?.({ type: "country", value: country })
              }
            >
              <span aria-hidden>{getCountryFlag(country)} </span>
              {host.infos?.country_name ?? country}
            </FilterChipText>
          ) : (
            "—"
          )}
        </KV>
        <KV label="AS">
          {asNum !== undefined ? (
            <FilterChipText
              highlighted={asnumHL?.has(String(asNum))}
              onClick={() =>
                onAddFilter?.({ type: "asnum", value: String(asNum) })
              }
            >
              {host.infos?.as_name
                ? `AS${asNum} (${host.infos.as_name})`
                : `AS${asNum}`}
            </FilterChipText>
          ) : (
            "—"
          )}
        </KV>
        <KV label="Source">
          {sources.length > 0 ? (
            <span className="flex flex-wrap gap-2">
              {sources.map((src, i) => (
                <FilterChipText
                  key={src}
                  highlighted={sourceHL?.has(src.toLowerCase())}
                  onClick={() =>
                    onAddFilter?.({ type: "source", value: src })
                  }
                >
                  {src}
                  {i < sources.length - 1 ? "," : ""}
                </FilterChipText>
              ))}
            </span>
          ) : (
            "—"
          )}
        </KV>
        <KV label="First seen">{formatTimestamp(host.starttime) || "—"}</KV>
        <KV label="Last seen">{formatTimestamp(host.endtime) || "—"}</KV>
      </Section>

      {host.hostnames && host.hostnames.length > 0 ? (
        <Section title="Hostnames">
          <ul className="space-y-1 font-mono text-xs">
            {host.hostnames.map((h) => (
              <li key={`${h.name}-${h.type ?? ""}`}>
                <button
                  type="button"
                  onClick={() =>
                    onAddFilter?.({ type: "hostname", value: h.name })
                  }
                  className={cn(
                    "rounded px-1 hover:underline",
                    hostnameHL?.has(h.name.toLowerCase()) &&
                      "bg-highlight text-highlight-foreground",
                  )}
                >
                  {h.name}
                </button>
                {h.type ? (
                  <span className="ml-2 text-muted-foreground">
                    ({h.type})
                  </span>
                ) : null}
              </li>
            ))}
          </ul>
        </Section>
      ) : null}

      {host.tags && host.tags.length > 0 ? (
        <Section title="Tags">
          <div className="flex flex-wrap gap-1.5">
            {visibleTags.map((tag) => (
              <button
                type="button"
                key={tag.value}
                onClick={() =>
                  onAddFilter?.({ type: "tag", value: tag.value })
                }
                title={tag.info?.join("\n")}
              >
                <Badge
                  className={cn(
                    "border-none",
                    getTagColor(tag.type),
                    tagHL?.has(tag.value.toLowerCase()) &&
                      "ring-2 ring-yellow-500 dark:ring-orange-400",
                  )}
                >
                  {tag.value}
                </Badge>
              </button>
            ))}
            {hasTagOverflow ? (
              <Button
                type="button"
                variant="link"
                size="sm"
                className="h-auto px-1 py-0 text-xs"
                aria-expanded={tagsExpanded}
                onClick={() => setTagsExpanded((v) => !v)}
              >
                {tagsExpanded ? (
                  <>
                    <ChevronUp className="size-3" />
                    Show less
                  </>
                ) : (
                  <>
                    <ChevronDown className="size-3" />
                    Show {hiddenTagCount} more
                  </>
                )}
              </Button>
            ) : null}
          </div>
        </Section>
      ) : null}

      {host.categories && host.categories.length > 0 ? (
        <Section title="Categories">
          <div className="flex flex-wrap gap-1.5">
            {host.categories.map((cat) => (
              <button
                type="button"
                key={cat}
                onClick={() =>
                  onAddFilter?.({ type: "category", value: cat })
                }
              >
                <Badge
                  variant="outline"
                  className={cn(
                    categoryHL?.has(cat.toLowerCase()) &&
                      "bg-highlight text-highlight-foreground",
                  )}
                >
                  {cat}
                </Badge>
              </button>
            ))}
          </div>
        </Section>
      ) : null}

      {host.ports && host.ports.length > 0 ? (
        <Section title="Ports & services">
          <ul className="space-y-3">
            {host.ports
              .filter((p) => typeof p.port === "number")
              .map((p) => {
                const token = formatPort(p);
                const isOpen = p.state_state === "open";
                const portMatch = portHL?.has(token);
                const serviceMatch =
                  p.service_name &&
                  serviceHL?.has(p.service_name.toLowerCase());
                const productMatch =
                  p.service_product &&
                  productHL?.has(p.service_product.toLowerCase());
                const portChip = (
                  <Badge
                    className={cn(
                      "border-none font-mono",
                      getPortColor(p.state_state),
                      (portMatch || serviceMatch || productMatch) &&
                        "ring-2 ring-yellow-500 dark:ring-orange-400",
                    )}
                  >
                    {token}
                  </Badge>
                );
                return (
                  <li
                    key={`p-${p.protocol}-${p.port}`}
                    className="space-y-1"
                  >
                    <div className="flex items-center gap-2">
                      {isOpen ? (
                        <button
                          type="button"
                          onClick={() => onAddFilter?.({ value: token })}
                        >
                          {portChip}
                        </button>
                      ) : (
                        portChip
                      )}
                      <span className="text-xs text-muted-foreground">
                        {p.state_state ?? "—"}
                      </span>
                      {p.service_name ? (
                        <span className="text-xs">
                          <button
                            type="button"
                            onClick={() =>
                              onAddFilter?.({
                                type: "service",
                                value: p.service_name as string,
                              })
                            }
                            className={cn(
                              "rounded px-1 font-semibold hover:underline",
                              serviceMatch &&
                                "bg-highlight text-highlight-foreground",
                            )}
                          >
                            {p.service_name}
                          </button>
                          {p.service_product ? (
                            <>
                              {" ("}
                              <button
                                type="button"
                                onClick={() =>
                                  onAddFilter?.({
                                    type: "product",
                                    value: p.service_product as string,
                                  })
                                }
                                className={cn(
                                  "rounded px-1 hover:underline",
                                  productMatch &&
                                    "bg-highlight text-highlight-foreground",
                                )}
                              >
                                {p.service_product}
                              </button>
                              {p.service_version ? ` ${p.service_version}` : ""}
                              {")"}
                            </>
                          ) : null}
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
                );
              })}
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

/** Plain-text-styled clickable filter trigger. Used in the
 *  ``Network`` section's ``KV`` rows where a full ``<Badge>`` would
 *  visually overpower the surrounding labels. */
function FilterChipText({
  children,
  highlighted,
  onClick,
}: {
  children: React.ReactNode;
  highlighted?: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        "rounded px-1 hover:underline",
        highlighted && "bg-highlight text-highlight-foreground",
      )}
    >
      {children}
    </button>
  );
}
