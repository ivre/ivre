import {
  ArrowLeft,
  ChevronLeft,
  ChevronRight,
  Copy,
  Link as LinkIcon,
  Printer,
} from "lucide-react";
import { useEffect, useRef, useState } from "react";
import {
  Link,
  useLocation,
  useParams,
  useSearchParams,
} from "react-router-dom";

import { HostNotesPanel } from "@/components/HostNotesPanel";
import { HostReport } from "@/components/HostReport";
import { ReportStatus } from "@/components/ReportStatus";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { useCount, useHosts, type HostPort, type HostRecord } from "@/lib/api";
import { copyText } from "@/lib/clipboard";
import { isModuleEnabled } from "@/lib/config";
import { buildQueryFromFilters, quoteValue } from "@/lib/filter";
import {
  formatTimestamp,
  getCountryFlag,
  getTagColor,
  sortTagsByImportance,
} from "@/lib/format";
import {
  hostRecordId,
  hostReportUrl,
  hostResultsUrl,
  readHostNavigation,
  type HostSection,
  type ReportTab,
} from "@/lib/host-report";
import { buildPagedQuery } from "@/lib/paging";
import { savedScrollPosition, usePageScroll } from "@/lib/use-page-scroll";
import { cn } from "@/lib/utils";
import { HostListRoute } from "./host-list";
import { PassiveRoute } from "./passive-list";

export function HostReportRoute({ sectionId }: { sectionId: HostSection }) {
  const { addr = "" } = useParams<{ addr: string }>();
  const [params, setParams] = useSearchParams();
  const headingRef = useRef<HTMLHeadingElement>(null);
  const reportRef = useRef<HTMLDivElement>(null);
  const location = useLocation();
  const navigation = readHostNavigation(location.state);
  const rawTab = params.get("tab");
  const tab: ReportTab =
    rawTab === "view" ||
    rawTab === "active" ||
    rawTab === "passive" ||
    rawTab === "notes"
      ? rawTab
      : sectionId;
  const available = isModuleEnabled(tab);
  const selectedId = params.get("record");
  const isScanReport = tab === "active" && Boolean(selectedId);
  const showView = isModuleEnabled("view");
  const showActive = isModuleEnabled("active");
  const showPassive = isModuleEnabled("passive");
  const showNotes = isModuleEnabled("notes");
  const exactQuery = `host:${quoteValue(addr)}`;
  const view = useHosts(showView ? "/view" : undefined, {
    q: buildPagedQuery(exactQuery, 1, 0),
  });
  const active = useHosts(isScanReport && showActive ? "/scans" : undefined, {
    q: buildPagedQuery(exactQuery, 1, 0),
    record: selectedId ?? undefined,
    includeId: true,
  });
  const activeCount = useCount(showActive ? "/scans/count" : undefined, {
    q: exactQuery,
  });
  const passiveCount = useCount(showPassive ? "/passive/count" : undefined, {
    q: exactQuery,
  });
  const selectedRecord = active.data?.find(
    (record) => hostRecordId(record) === selectedId,
  );
  const missingIds = active.data?.some((record) => !hostRecordId(record));
  const host = isScanReport
    ? selectedRecord
    : tab === "view"
      ? view.data?.[0]
      : undefined;
  const [wrap, setWrap] = useState(true);
  const ready =
    tab === "view"
      ? !view.isLoading
      : isScanReport
        ? !active.isLoading
        : tab === "notes" || !available;
  usePageScroll(ready, 0, {
    section: params.get("section"),
    root: reportRef,
  });

  useEffect(() => {
    document.title = `IVRE — ${addr} — ${tab === "active" ? "Active scans" : tab === "view" ? "View" : tab === "passive" ? "Passive" : "Notes"}`;
  }, [addr, tab]);

  const cameFromHostBrowser = Boolean(
    navigation?.returnTo.split("?")[0].includes("/host/"),
  );
  const reportNavigation = readHostNavigation({
    hostNavigation: location.state?.reportNavigation,
  });
  const browserState =
    isScanReport && cameFromHostBrowser
      ? {
          hostNavigation: reportNavigation,
          reportPaging: location.state?.reportPaging,
        }
      : location.state;
  const reportLink = (patch: Record<string, string | null>) => {
    const next = new URLSearchParams(params);
    for (const [key, value] of Object.entries(patch)) {
      if (value === null || value === "") next.delete(key);
      else next.set(key, value);
    }
    return { to: hostReportUrl(sectionId, addr, next), state: location.state };
  };
  const tabLink = (source: ReportTab) => ({
    ...reportLink({
      tab: source,
      section: null,
      record: null,
    }),
    state: browserState,
  });
  const sectionLink = (id: string) => reportLink({ section: id });
  const relatedLink = (
    source: "view" | "active" | "passive",
    port: HostPort,
  ) => {
    const base = new URLSearchParams(params);
    for (const key of [
      "section",
      "record",
      "recordsSkip",
      "passiveSkip",
      "passivePort",
      "passiveType",
      "passiveSensor",
    ])
      base.delete(key);
    base.set("tab", source);
    if (source === "passive") base.set("passiveQ", `tcp/${port.port}`);
    else if (source === "active") {
      const state = port.state_state;
      if (state !== "open" && state !== "closed" && state !== "filtered")
        return undefined;
      base.set(
        "activeQ",
        buildQueryFromFilters([
          { type: state, value: `${port.protocol}/${port.port}` },
        ]),
      );
    } else
      base.set(
        "section",
        `port-${encodeURIComponent(port.protocol)}-${port.port}`,
      );
    return { to: hostReportUrl(sectionId, addr, base), state: browserState };
  };
  const backTo =
    navigation?.returnTo ??
    (isScanReport ? tabLink("active").to : hostResultsUrl(sectionId, params));
  const backToBrowser = cameFromHostBrowser || (isScanReport && !navigation);
  const contextIndex = navigation?.currentIndex;
  const selectedIndex =
    contextIndex !== undefined &&
    navigation?.entries[contextIndex]?.addr === addr
      ? contextIndex
      : (navigation?.entries.findIndex(
          (item) =>
            item.addr === addr && (!item.record || item.record === selectedId),
        ) ?? -1);
  const neighborLink = (offset: number) => {
    const entry = navigation?.entries[selectedIndex + offset];
    if (selectedIndex < 0 || !entry) return undefined;
    const next = new URLSearchParams(params);
    next.set("tab", tab);
    for (const key of [
      "record",
      "section",
      "passiveSkip",
      "passivePort",
      "passiveType",
      "passiveSensor",
    ])
      next.delete(key);
    if (tab === "active" && entry.record) next.set("record", entry.record);
    else next.delete("recordsSkip");
    return {
      to: hostReportUrl(sectionId, entry.addr, next),
      state: {
        ...location.state,
        hostNavigation: {
          ...navigation,
          currentIndex: selectedIndex + offset,
        },
      },
    };
  };
  const prev = neighborLink(-1);
  const next = neighborLink(1);
  const contextHost = host ?? view.data?.[0];
  const copyPermalink = () => {
    const url = new URL(window.location.href);
    url.hash = hostReportUrl(sectionId, addr, params);
    return copyText(url.href, "Permalink copied");
  };
  const backToTop = () => {
    const next = new URLSearchParams(params);
    next.delete("section");
    setParams(next, { replace: true, state: location.state });
    headingRef.current?.focus({ preventScroll: true });
  };

  return (
    <article
      className="mx-auto max-w-[1440px] px-4 pb-16 pt-5 sm:px-8 lg:px-10"
      aria-label={`IP report for ${addr}`}
    >
      <div className="mb-6 flex flex-wrap items-center justify-between gap-3 text-sm print:hidden">
        <Link
          to={backTo}
          state={{
            hostNavigation: backToBrowser ? reportNavigation : undefined,
            reportPaging: location.state?.reportPaging,
            restoreScrollY:
              savedScrollPosition(navigation?.returnKey) ??
              navigation?.returnScrollY ??
              0,
          }}
          className="inline-flex items-center gap-2 text-primary hover:underline"
        >
          <ArrowLeft className="size-4" />
          {backToBrowser ? "Back to active scans" : "Back to results"}
        </Link>
        {navigation ? (
          <div className="flex gap-2">
            {prev ? (
              <Button variant="ghost" size="sm" asChild>
                <Link {...prev}>
                  <ChevronLeft />
                  {isScanReport ? "Previous scan" : "Previous host"}
                </Link>
              </Button>
            ) : (
              <Button variant="ghost" size="sm" disabled>
                <ChevronLeft />
                {isScanReport ? "Previous scan" : "Previous host"}
              </Button>
            )}
            {next ? (
              <Button variant="ghost" size="sm" asChild>
                <Link {...next}>
                  {isScanReport ? "Next scan" : "Next host"}
                  <ChevronRight />
                </Link>
              </Button>
            ) : (
              <Button variant="ghost" size="sm" disabled>
                {isScanReport ? "Next scan" : "Next host"}
                <ChevronRight />
              </Button>
            )}
          </div>
        ) : null}
      </div>
      <header>
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="min-w-0">
            <h1
              ref={headingRef}
              tabIndex={-1}
              className="break-all font-mono text-3xl font-semibold tracking-tight"
            >
              {addr}
            </h1>
            {contextHost?.hostnames?.length ? (
              <Hostnames key={addr} host={contextHost} />
            ) : null}
          </div>
          <div className="flex flex-wrap gap-2 print:hidden">
            <Button
              variant="outline"
              size="sm"
              onClick={() => copyText(addr, "IP address copied")}
            >
              <Copy />
              Copy IP
            </Button>
            <Button
              variant="outline"
              size="sm"
              aria-label="Copy permalink"
              onClick={copyPermalink}
            >
              <LinkIcon />
              Copy link
            </Button>
            <Button variant="outline" size="sm" onClick={() => window.print()}>
              <Printer />
              Print
            </Button>
          </div>
        </div>
        {contextHost ? (
          <HostMetadata
            key={`${addr}-${tab}`}
            host={contextHost}
            sourceLabel={isScanReport && host ? "Scan sources" : "View sources"}
          />
        ) : (
          <p className="my-4 text-sm text-muted-foreground">
            Evidence for this IP address
          </p>
        )}
      </header>
      <nav
        aria-label="Host evidence sources"
        className="mb-5 flex gap-6 overflow-x-auto border-b border-border print:hidden"
      >
        {(
          [
            ["view", "View", showView, undefined],
            ["active", "Active scans", showActive, activeCount.data],
            ["passive", "Passive", showPassive, passiveCount.data],
            ["notes", "Notes", showNotes, undefined],
          ] as const
        ).map(([id, label, enabled, count]) =>
          enabled ? (
            <Link
              key={id}
              {...tabLink(id)}
              aria-current={tab === id ? "page" : undefined}
              className={cn(
                "flex items-center gap-2 whitespace-nowrap border-b-2 border-transparent py-3 text-sm text-muted-foreground hover:text-foreground",
                tab === id && "border-primary font-semibold text-foreground",
              )}
            >
              {label}
              {count !== undefined ? (
                <span className="rounded bg-muted px-1.5 text-xs font-normal">
                  {count}
                </span>
              ) : null}
            </Link>
          ) : (
            <span
              key={id}
              className="whitespace-nowrap py-3 text-sm text-muted-foreground/60"
              title="Not exposed by this server"
            >
              {label} · unavailable
            </span>
          ),
        )}
      </nav>
      <div className="mb-6 flex flex-wrap items-start justify-between gap-4">
        <div>
          <h2 className="text-base font-semibold">
            {tab === "view"
              ? "Merged observations"
              : tab === "active"
                ? isScanReport
                  ? "Individual active scan"
                  : "Active scan evidence"
                : tab === "passive"
                  ? "Passive evidence"
                  : "IP notes"}
          </h2>
          <p className="mt-1 text-sm text-muted-foreground">
            {tab === "view"
              ? "Combined evidence, not a live status check."
              : tab === "active"
                ? isScanReport
                  ? "A single observation, kept separate from the merged View."
                  : "Scan history for this IP, with timeline and source filters."
                : tab === "passive"
                  ? "Observed traffic and protocol evidence, not current port status."
                  : "Operator context, separate from scanner and traffic observations."}
          </p>
          {host && (tab === "view" || isScanReport) ? (
            <p className="mt-1 text-xs text-muted-foreground">
              First observed: {formatTimestamp(host.starttime) || "unknown"} ·
              Last observed: {formatTimestamp(host.endtime) || "unknown"} · UTC
            </p>
          ) : null}
        </div>
        {available && (tab === "view" || isScanReport) ? (
          <Button
            variant="outline"
            size="sm"
            aria-pressed={wrap}
            onClick={() => setWrap(!wrap)}
            className="print:hidden"
          >
            Line wrapping: {wrap ? "on" : "off"}
          </Button>
        ) : null}
      </div>
      {!available ? (
        <p className="py-10 text-muted-foreground">
          This source is not exposed by this server. Choose an available source
          above.
        </p>
      ) : (
        <>
          {isScanReport ? (
            <>
              {selectedRecord?.categories?.length ? (
                <p className="mb-5 text-sm text-muted-foreground">
                  Categories: {selectedRecord.categories.join(", ")}
                </p>
              ) : null}
              <ReportStatus
                loading={active.isLoading && !selectedRecord}
                error={active.error}
                empty={
                  !active.isLoading && !active.error && !selectedRecord
                    ? missingIds
                      ? "The server did not return database identifiers. Update the server to open individual scan reports."
                      : "This active scan record is no longer available for this IP address."
                    : undefined
                }
              />
              {selectedId && !selectedRecord ? (
                <Link
                  {...tabLink("active")}
                  className="mb-6 inline-block text-primary hover:underline"
                >
                  Browse active scans →
                </Link>
              ) : null}
            </>
          ) : null}
          {tab === "view" ? (
            <>
              <ReportStatus
                loading={view.isLoading}
                error={view.error}
                empty={
                  !view.isLoading && !view.error && !host
                    ? "No merged View record for this IP address. Active scans and Passive evidence may still be available."
                    : undefined
                }
              />
              {!view.isLoading && !view.error && !host ? (
                <div className="mb-6 flex gap-5 text-sm">
                  {showActive ? (
                    <Link
                      {...tabLink("active")}
                      className="text-primary hover:underline"
                    >
                      Browse active scans →
                    </Link>
                  ) : null}
                  {showPassive ? (
                    <Link
                      {...tabLink("passive")}
                      className="text-primary hover:underline"
                    >
                      Browse passive observations →
                    </Link>
                  ) : null}
                </div>
              ) : null}
            </>
          ) : null}
          {(tab === "view" || isScanReport) && host ? (
            <HostReport
              ref={reportRef}
              key={`${addr}-${tab}-${tab === "active" ? selectedId : "view"}`}
              host={host}
              active={tab === "active"}
              wrap={wrap}
              sectionLink={sectionLink}
              relatedLink={relatedLink}
              showView={showView}
              showActive={showActive}
              showPassive={showPassive}
              onBackToTop={backToTop}
            />
          ) : null}
          {tab === "active" && !isScanReport ? (
            <HostListRoute key={addr} sectionId="active" scopeAddr={addr} />
          ) : null}
          {tab === "passive" ? (
            <PassiveRoute key={addr} scopeAddr={addr} />
          ) : null}
          {tab === "notes" ? (
            <HostNotesPanel key={addr} addr={addr} showUnavailable />
          ) : null}
        </>
      )}
    </article>
  );
}

function Hostnames({ host }: { host: HostRecord }) {
  const [expanded, setExpanded] = useState(false);
  const names = host.hostnames ?? [];
  return (
    <div className="mt-1 flex max-w-3xl flex-wrap items-baseline gap-x-3 gap-y-1 text-sm">
      {(expanded ? names : names.slice(0, 4)).map((item, index) => (
        <span key={index} className="break-all" title={item.type}>
          {item.name}
        </span>
      ))}
      {names.length > 4 ? (
        <button
          className="text-primary hover:underline"
          aria-expanded={expanded}
          onClick={() => setExpanded(!expanded)}
        >
          {expanded
            ? "Show fewer names"
            : `Show ${names.length - 4} more names`}
        </button>
      ) : null}
    </div>
  );
}

function HostMetadata({
  host,
  sourceLabel,
}: {
  host: HostRecord;
  sourceLabel: string;
}) {
  const [expanded, setExpanded] = useState(false);
  const tags = sortTagsByImportance(host.tags ?? []);
  const sources = Array.isArray(host.source)
    ? host.source
    : host.source
      ? [host.source]
      : [];
  return (
    <div className="my-4 space-y-3">
      <div className="flex flex-wrap gap-x-5 gap-y-1 text-sm text-muted-foreground">
        {host.infos?.country_code ? (
          <span>
            {getCountryFlag(host.infos.country_code)}{" "}
            {host.infos.country_name ?? host.infos.country_code}
          </span>
        ) : null}
        {host.infos?.as_num !== undefined ? (
          <span>
            AS{host.infos.as_num}
            {host.infos.as_name ? ` · ${host.infos.as_name}` : ""}
          </span>
        ) : null}
        {sources.length ? (
          <span className="break-all">
            {sourceLabel}: {sources.join(", ")}
          </span>
        ) : null}
      </div>
      {tags.length ? (
        <div className="flex flex-wrap gap-1.5">
          {(expanded ? tags : tags.slice(0, 12)).map((tag, index) => (
            <Badge
              key={index}
              title={tag.info?.join("\n")}
              className={cn(
                "max-w-full whitespace-normal break-words border-none",
                getTagColor(tag.type),
              )}
            >
              {tag.value}
            </Badge>
          ))}
          {tags.length > 12 ? (
            <button
              className="px-1 text-xs text-primary hover:underline"
              aria-expanded={expanded}
              onClick={() => setExpanded(!expanded)}
            >
              {expanded ? "Show less" : `Show ${tags.length - 12} more tags`}
            </button>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}
