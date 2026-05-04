import { ArrowRight } from "lucide-react";

import { DomainTree } from "@/components/DomainTree";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import type { HostRecord } from "@/lib/api";
import type { Filter, HighlightMap } from "@/lib/filter";
import {
  formatPort,
  formatServices,
  getCountryFlag,
  getPortColor,
  getTagColor,
} from "@/lib/format";
import { cn } from "@/lib/utils";

export interface HostCardProps {
  host: HostRecord;
  /** Add a filter when the user clicks a chip on this card. */
  onAddFilter?: (filter: Filter) => void;
  /** Open the host detail panel for this host. */
  onSelect?: (host: HostRecord) => void;
  /** Map of currently-active typed filters used for highlighting. */
  highlights?: HighlightMap;
  /** ``true`` when the corresponding row in the section's
   *  ``<Timeline>`` is currently hovered. Adds an orange ring
   *  around the card to mirror the highlight (same convention as
   *  :type:`PassiveRecordCardProps`). */
  highlighted?: boolean;
  /** Pointer-enter callback — used by the route to sync the
   *  hover state back to the timeline. */
  onHover?: () => void;
  /** Pointer-leave callback. */
  onLeave?: () => void;
  /** DOM ref forwarded by the parent so the timeline can
   *  ``scrollIntoView`` the card on click. */
  innerRef?: (el: HTMLDivElement | null) => void;
}

export function HostCard({
  host,
  onAddFilter,
  onSelect,
  highlights,
  highlighted,
  onHover,
  onLeave,
  innerRef,
}: HostCardProps) {
  const country = host.infos?.country_code;
  const countryName = host.infos?.country_name ?? country;
  const asNum = host.infos?.as_num;
  const asName = host.infos?.as_name;
  // Coerce ``source`` to an array. Active scan documents
  // (``db.nmap``) store it as a single string; view records
  // (``db.view``) carry the merged array. The TypeScript type
  // declares it as ``string[]?`` but the wire shape is wider, so
  // we accept either form here rather than crashing in
  // ``sources.map()`` below.
  const sources: string[] = Array.isArray(host.source)
    ? host.source
    : host.source
      ? [host.source]
      : [];

  const countryHL = highlights?.get("country");
  const asnumHL = highlights?.get("asnum");
  const sourceHL = highlights?.get("source");
  const categoryHL = highlights?.get("category");
  const tagHL = highlights?.get("tag");
  const portHL = highlights?.get("port");
  const serviceHL = highlights?.get("service");
  const productHL = highlights?.get("product");
  const domainHL = highlights?.get("domain");
  const hostnameHL = highlights?.get("hostname");

  return (
    // Soften the card chrome compared to shadcn's default ``<Card>``:
    // light-grey border that barely separates the card from the page
    // background in light mode, dark-blue border that blends into
    // the deep-blue surface in dark mode. Drop the default ``shadow-sm``
    // (Card adds it for free); only show a shadow on hover.
    //
    // ``py-0`` overrides shadcn's default ``py-6`` on Card itself so
    // the inside-card padding comes solely from ``<CardContent>``'s
    // ``p-4`` (1 rem all around) — no stacked top/bottom dead space.
    <Card
      ref={innerRef}
      onMouseEnter={onHover}
      onMouseLeave={onLeave}
      className={cn(
        "border-gray-200/60 py-0 shadow-none transition-shadow hover:shadow-sm dark:border-blue-950/60",
        highlighted && "ring-2 ring-orange-400 dark:ring-orange-300",
      )}
    >
      <CardContent className="space-y-3 p-4">
        <div className="flex items-start justify-between gap-4">
          <h3 className="font-mono text-lg font-semibold">{host.addr}</h3>
          <Button
            variant="link"
            size="sm"
            className="-mr-2"
            onClick={() => onSelect?.(host)}
          >
            Details <ArrowRight className="size-4" />
          </Button>
        </div>

        {/* Country / AS / Source */}
        <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
          {country ? (
            <button
              type="button"
              className={cn(
                "rounded px-1 hover:underline",
                countryHL?.has(country.toLowerCase()) &&
                  "bg-highlight text-highlight-foreground",
              )}
              onClick={() =>
                onAddFilter?.({ type: "country", value: country })
              }
            >
              <span aria-hidden>{getCountryFlag(country)}</span> {countryName}
            </button>
          ) : null}
          {asNum !== undefined ? (
            <button
              type="button"
              className={cn(
                "rounded px-1 hover:underline",
                asnumHL?.has(String(asNum)) &&
                  "bg-highlight text-highlight-foreground",
              )}
              onClick={() =>
                onAddFilter?.({ type: "asnum", value: String(asNum) })
              }
            >
              {asName ? `AS${asNum} ${asName}` : `AS${asNum}`}
            </button>
          ) : null}
          {sources.map((src) => (
            <button
              type="button"
              key={src}
              className={cn(
                "rounded px-1 hover:underline",
                sourceHL?.has(src.toLowerCase()) &&
                  "bg-highlight text-highlight-foreground",
              )}
              onClick={() => onAddFilter?.({ type: "source", value: src })}
            >
              {src}
            </button>
          ))}
        </div>

        {/* Hostnames */}
        {host.hostnames && host.hostnames.length > 0 ? (
          <DomainTree
            hostnames={host.hostnames}
            highlightedDomains={domainHL}
            highlightedHostnames={hostnameHL}
            onAddDomainFilter={(d) =>
              onAddFilter?.({ type: "domain", value: d })
            }
            onAddHostnameFilter={(h) =>
              onAddFilter?.({ type: "hostname", value: h })
            }
          />
        ) : null}

        {/* Categories + tags chips */}
        {(host.categories?.length ?? 0) > 0 ||
        (host.tags?.length ?? 0) > 0 ? (
          <div className="flex flex-wrap gap-1.5">
            {host.categories?.map((cat) => (
              <button
                type="button"
                key={`cat-${cat}`}
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
            {host.tags?.map((tag) => (
              <button
                type="button"
                key={`tag-${tag.value}`}
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
          </div>
        ) : null}

        {/* Ports */}
        {host.ports && host.ports.length > 0 ? (
          <div>
            <div className="mb-1 text-xs font-semibold text-muted-foreground">
              Ports:
            </div>
            <div className="flex flex-wrap gap-1.5">
              {host.ports
                .filter((p) => typeof p.port === "number")
                .map((p) => {
                  const token = formatPort(p);
                  const isOpen = p.state_state === "open";
                  const productMatch =
                    p.service_product &&
                    productHL?.has(p.service_product.toLowerCase());
                  const serviceMatch =
                    p.service_name &&
                    serviceHL?.has(p.service_name.toLowerCase());
                  const portMatch = portHL?.has(token);
                  const highlighted =
                    portMatch || productMatch || serviceMatch;
                  return isOpen ? (
                    <button
                      type="button"
                      key={`p-${token}`}
                      onClick={() => onAddFilter?.({ value: token })}
                    >
                      <Badge
                        className={cn(
                          "border-none font-mono",
                          getPortColor(p.state_state),
                          highlighted && "ring-2 ring-yellow-500 dark:ring-orange-400",
                        )}
                      >
                        {token}
                      </Badge>
                    </button>
                  ) : (
                    <Badge
                      key={`p-${token}`}
                      className={cn(
                        "border-none font-mono",
                        getPortColor(p.state_state),
                      )}
                    >
                      {token}
                    </Badge>
                  );
                })}
            </div>
          </div>
        ) : null}

        {/* Services preview */}
        {host.ports && host.ports.length > 0 ? (
          <div className="text-xs text-muted-foreground">
            <span className="font-semibold">Services:</span>{" "}
            {formatServices(host.ports) || (
              <span className="italic">none</span>
            )}
          </div>
        ) : null}
      </CardContent>
    </Card>
  );
}
