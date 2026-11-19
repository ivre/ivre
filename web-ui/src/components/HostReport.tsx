import { useEffect, useMemo, useState, type ReactNode, type Ref } from "react";
import { Link, type LinkProps } from "react-router-dom";
import { ArrowUp } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import type { HostPort, HostRecord, HostScript } from "@/lib/api";
import { copyText } from "@/lib/clipboard";
import { getPortColor } from "@/lib/format";
import { cn } from "@/lib/utils";

type ReportLink = Pick<LinkProps, "to" | "state">;

export interface HostReportProps {
  ref?: Ref<HTMLDivElement>;
  host: HostRecord;
  wrap: boolean;
  sectionLink: (id: string) => ReportLink;
  relatedLink: (
    source: "view" | "active" | "passive",
    port: HostPort,
  ) => ReportLink | undefined;
  active: boolean;
  showView: boolean;
  showActive: boolean;
  showPassive: boolean;
  onBackToTop?: () => void;
}

function portId(port: HostPort): string {
  return `port-${encodeURIComponent(port.protocol)}-${port.port}`;
}

/** Only embedded PNG/JPEG screenshots may be displayed. Ingested URLs and
 * SVG/HTML payloads must never become fetches or executable documents. */
function screenshotSource(port: HostPort): string | undefined {
  const data = port.screenshot === "field" ? port.screendata : undefined;
  if (!data || !/^[A-Za-z0-9+/=\r\n]+$/.test(data)) return;
  if (data.startsWith("/9j/")) return `data:image/jpeg;base64,${data}`;
  if (data.startsWith("iVBORw0KGgo")) return `data:image/png;base64,${data}`;
}

export function HostReport({
  ref,
  host,
  wrap,
  sectionLink,
  relatedLink,
  active,
  showView,
  showActive,
  showPassive,
  onBackToTop,
}: HostReportProps) {
  const ports = useMemo(
    () =>
      (host.ports ?? [])
        .filter((port) => Number.isInteger(port.port) && port.port >= 0)
        .sort(
          (a, b) => a.protocol.localeCompare(b.protocol) || a.port - b.port,
        ),
    [host],
  );
  const hostScripts = [
    ...(host.scripts ?? []),
    ...(host.ports ?? [])
      .filter((port) => port.port === -1)
      .flatMap((port) => port.scripts ?? []),
  ];
  const osClasses = [
    ...(host.os?.osclass ?? []),
    ...(host.os?.osmatch ?? []).flatMap((match) => match.osclass ?? []),
  ];
  const navigation = [
    ...ports.map((port) => ({
      id: portId(port),
      label: `${port.port}/${port.protocol}${port.service_name ? ` · ${port.service_name}` : ""}`,
    })),
    ...(hostScripts.length
      ? [{ id: "host-scripts", label: "Host scripts" }]
      : []),
    ...(host.traces?.length
      ? [{ id: "traceroutes", label: "Traceroutes" }]
      : []),
    ...(host.os || host.cpes?.length ? [{ id: "os", label: "OS / CPEs" }] : []),
    ...(host.addresses?.mac?.length || host.extraports
      ? [{ id: "other", label: "Other observations" }]
      : []),
  ];
  const [visibleSection, setVisibleSection] = useState("");

  useEffect(() => {
    const update = () => {
      const sections = [
        ...document.querySelectorAll<HTMLElement>("[data-report-section]"),
      ];
      let current = sections[0]?.id ?? "";
      for (const item of sections)
        if (item.getBoundingClientRect().top <= 140) current = item.id;
      setVisibleSection(current);
    };
    window.addEventListener("scroll", update, { passive: true });
    const frame = requestAnimationFrame(update);
    return () => {
      cancelAnimationFrame(frame);
      window.removeEventListener("scroll", update);
    };
  }, [host]);

  return (
    <div
      ref={ref}
      data-host-report
      className="grid min-w-0 gap-6 lg:grid-cols-[11.5rem_minmax(0,1fr)] lg:gap-10"
    >
      <nav
        aria-label="Report sections"
        className="flex flex-wrap gap-1 self-start lg:sticky lg:top-20 lg:max-h-[calc(100vh-6rem)] lg:flex-col lg:overflow-y-auto print:hidden"
      >
        {!active && onBackToTop ? (
          <Button
            variant="ghost"
            className="mb-2 w-full justify-start px-3 text-muted-foreground"
            onClick={onBackToTop}
          >
            <ArrowUp className="size-4" aria-hidden />
            Back to top
          </Button>
        ) : null}
        <p className="w-full px-3 pb-2 text-[11px] font-semibold uppercase tracking-widest text-muted-foreground">
          On this page
        </p>
        {navigation.map((item) => (
          <Link
            key={item.id}
            {...sectionLink(item.id)}
            aria-current={visibleSection === item.id ? "location" : undefined}
            className={cn(
              "min-w-0 break-words border-l-2 border-transparent px-3 py-2 text-sm text-muted-foreground hover:bg-accent hover:text-foreground",
              visibleSection === item.id &&
                "border-primary bg-primary/5 text-primary",
            )}
          >
            {item.label}
          </Link>
        ))}
      </nav>
      <div className="min-w-0">
        {navigation.length === 0 ? (
          <p className="border-t py-8 text-muted-foreground">
            No port, script, or host-level details in this record.
          </p>
        ) : null}
        {ports.map((port) => {
          const id = portId(port);
          const screenshot = screenshotSource(port);
          const viewLink =
            active && showView ? relatedLink("view", port) : undefined;
          const activeLink =
            !active && showActive ? relatedLink("active", port) : undefined;
          const passiveLink = showPassive
            ? relatedLink("passive", port)
            : undefined;
          return (
            <ReportSection key={id} id={id}>
              <div className="flex flex-wrap items-center gap-3">
                <h2 className="font-mono text-xl font-semibold">
                  <Link {...sectionLink(id)} className="hover:underline">
                    {port.port}/{port.protocol}
                  </Link>
                </h2>
                <Badge
                  className={cn(
                    "border-none uppercase",
                    getPortColor(port.state_state),
                  )}
                >
                  {port.state_state ?? "unknown"}
                </Badge>
                <span>{port.service_name ?? "Unidentified service"}</span>
              </div>
              <p className="mt-1 break-words text-sm text-muted-foreground">
                {[
                  port.service_product,
                  port.service_version,
                  port.service_extrainfo,
                ]
                  .filter(Boolean)
                  .join(" · ") || "No product information"}
              </p>
              {port.service_hostname ||
              port.service_ostype ||
              port.service_devicetype ||
              port.service_tunnel ||
              port.state_reason ? (
                <dl className="mt-3 flex flex-wrap gap-x-6 gap-y-1 text-sm">
                  {[
                    ["Hostname", port.service_hostname],
                    ["OS", port.service_ostype],
                    ["Device", port.service_devicetype],
                    ["Tunnel", port.service_tunnel],
                    ["State reason", port.state_reason],
                  ]
                    .filter(([, value]) => value)
                    .map(([label, value]) => (
                      <div key={label} className="flex gap-2 break-all">
                        <dt className="text-muted-foreground">{label}:</dt>
                        <dd>{value}</dd>
                      </div>
                    ))}
                </dl>
              ) : null}
              {screenshot ? (
                <figure className="my-6">
                  <img
                    src={screenshot}
                    alt={`Screenshot of ${host.addr} port ${port.port}/${port.protocol}`}
                    loading="lazy"
                    decoding="async"
                    className="max-h-[40rem] max-w-full rounded border object-contain object-left"
                  />
                  <figcaption className="mt-2 text-xs text-muted-foreground">
                    Screenshot from this observation
                  </figcaption>
                </figure>
              ) : null}
              {port.scripts?.length ? (
                port.scripts.map((script, index) => (
                  <ScriptOutput
                    key={`${script.id}-${index}`}
                    script={script}
                    wrap={wrap}
                    id={`${id}-${encodeURIComponent(script.id)}-${index}`}
                    sectionLink={sectionLink}
                  />
                ))
              ) : (
                <p className="my-6 text-sm text-muted-foreground">
                  No script output for this port.
                </p>
              )}
              <div className="mt-5 flex flex-wrap gap-x-5 gap-y-2 text-sm print:hidden">
                <span className="text-muted-foreground">Related evidence:</span>
                {viewLink ? (
                  <Link {...viewLink} className="text-primary hover:underline">
                    Merged View →
                  </Link>
                ) : null}
                {!active && showActive ? (
                  activeLink ? (
                    <Link
                      {...activeLink}
                      className="text-primary hover:underline"
                    >
                      Active scans →
                    </Link>
                  ) : (
                    <span
                      className="text-muted-foreground"
                      title="This port's state is missing or unsupported by the scan filter."
                    >
                      Active scans unavailable
                    </span>
                  )
                ) : null}
                {passiveLink ? (
                  <Link
                    {...passiveLink}
                    className="text-primary hover:underline"
                  >
                    Passive observations →
                  </Link>
                ) : null}
              </div>
            </ReportSection>
          );
        })}
        {hostScripts.length ? (
          <ReportSection id="host-scripts" title="Host scripts">
            {hostScripts.map((script, index) => (
              <ScriptOutput
                key={`${script.id}-${index}`}
                script={script}
                wrap={wrap}
                id={`host-scripts-${encodeURIComponent(script.id)}-${index}`}
                sectionLink={sectionLink}
              />
            ))}
          </ReportSection>
        ) : null}
        {host.traces?.length ? (
          <ReportSection id="traceroutes" title="Traceroutes">
            {host.traces.map((trace, index) => (
              <div key={index} className="mt-5">
                <p className="mb-3 text-sm text-muted-foreground">
                  Using {trace.protocol ?? "unknown protocol"}
                  {trace.port !== undefined ? `/${trace.port}` : ""}
                </p>
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-sm">
                    <thead>
                      <tr className="border-b text-muted-foreground">
                        <th scope="col" className="p-2">
                          Hop
                        </th>
                        <th scope="col" className="p-2">
                          Address / hostname
                        </th>
                        <th scope="col" className="p-2">
                          RTT (ms)
                        </th>
                      </tr>
                    </thead>
                    <tbody>
                      {[...(trace.hops ?? [])]
                        .sort((a, b) => a.ttl - b.ttl)
                        .map((hop, hopIndex) => (
                          <tr key={hopIndex} className="border-b">
                            <td className="p-2 font-mono">{hop.ttl}</td>
                            <td className="break-all p-2 font-mono">
                              {hop.ipaddr ?? "—"}
                              {hop.host ? ` (${hop.host})` : ""}
                            </td>
                            <td className="p-2 font-mono">{hop.rtt ?? "—"}</td>
                          </tr>
                        ))}
                    </tbody>
                  </table>
                </div>
              </div>
            ))}
          </ReportSection>
        ) : null}
        {host.os || host.cpes?.length ? (
          <ReportSection id="os" title="OS / CPEs">
            <p className="my-3 text-sm text-muted-foreground">
              Detection reflects scan observations, not verified inventory.
            </p>
            {host.os?.osmatch?.map((match, index) => (
              <p key={index} className="my-2">
                {match.name ?? "OS match"}
                {match.accuracy !== undefined
                  ? ` · accuracy ${match.accuracy}%`
                  : ""}
              </p>
            ))}
            {osClasses.map((item, index) => (
              <p key={index} className="my-2 text-sm">
                {[item.type, item.vendor, item.osfamily, item.osgen]
                  .filter(Boolean)
                  .join(" / ")}
                {item.accuracy !== undefined
                  ? ` · accuracy ${item.accuracy}%`
                  : ""}
              </p>
            ))}
            {host.cpes?.length ? (
              <div className="mt-4 overflow-x-auto">
                <table className="w-full text-left text-sm">
                  <caption className="sr-only">
                    Common Platform Enumeration
                  </caption>
                  <thead>
                    <tr className="border-b text-muted-foreground">
                      {["Type", "Vendor", "Product", "Version"].map((label) => (
                        <th key={label} scope="col" className="p-2">
                          {label}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {host.cpes.map((cpe, index) => (
                      <tr key={index} className="border-b">
                        {[cpe.type, cpe.vendor, cpe.product, cpe.version].map(
                          (value, field) => (
                            <td key={field} className="break-all p-2 font-mono">
                              {value || "—"}
                            </td>
                          ),
                        )}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : null}
          </ReportSection>
        ) : null}
        {host.addresses?.mac?.length || host.extraports ? (
          <ReportSection id="other" title="Other observations">
            {host.addresses?.mac?.map((mac, index) => (
              <p key={index} className="my-3 text-sm">
                MAC address: <span className="font-mono">{mac.addr}</span>
                {mac.manuf ? ` · ${mac.manuf}` : ""}
              </p>
            ))}
            {Object.entries(host.extraports ?? {}).map(([status, info]) => (
              <p key={status} className="my-3 text-sm">
                {info.total ?? "Unknown number of"} additional ports {status}
                {info.reasons
                  ? ` · ${Object.entries(info.reasons)
                      .map(([reason, count]) => `${count} ${reason}`)
                      .join(", ")}`
                  : ""}
              </p>
            ))}
          </ReportSection>
        ) : null}
      </div>
    </div>
  );
}

function ReportSection({
  id,
  title,
  children,
}: {
  id: string;
  title?: string;
  children: ReactNode;
}) {
  return (
    <section
      id={id}
      tabIndex={-1}
      data-report-section
      className="scroll-mt-20 border-t border-border py-7 first:border-t-2 first:border-foreground first:pt-4 focus-visible:outline focus-visible:outline-2 focus-visible:outline-ring"
    >
      {title ? <h2 className="text-xl font-semibold">{title}</h2> : null}
      {children}
    </section>
  );
}

function ScriptOutput({
  script,
  wrap,
  id,
  sectionLink,
}: {
  script: HostScript;
  wrap: boolean;
  id: string;
  sectionLink: (id: string) => ReportLink;
}) {
  const [open, setOpen] = useState(true);
  const structured = Object.fromEntries(
    Object.entries(script).filter(([key]) => key !== "id" && key !== "output"),
  );
  const text =
    script.output ||
    (Object.keys(structured).length
      ? JSON.stringify(structured, null, 2)
      : "No output.");
  return (
    <div id={id} tabIndex={-1} className="my-6 scroll-mt-20">
      <div className="mb-2 flex items-center justify-between gap-3">
        <h3 className="min-w-0 break-all font-mono text-sm font-semibold">
          <Link {...sectionLink(id)} className="hover:underline">
            {script.id}
          </Link>
        </h3>
        <div className="flex shrink-0 gap-1 print:hidden">
          <Button
            variant="ghost"
            size="sm"
            onClick={() => copyText(text)}
            aria-label={`Copy ${script.id} output`}
          >
            Copy
          </Button>
          <Button
            variant="ghost"
            size="sm"
            aria-expanded={open}
            aria-controls={`${id}-output`}
            onClick={() => setOpen(!open)}
            aria-label={`${open ? "Collapse" : "Expand"} ${script.id}`}
          >
            {open ? "Collapse" : "Expand"}
          </Button>
        </div>
      </div>
      <pre
        id={`${id}-output`}
        hidden={!open}
        className={cn(
          "host-report-output border-l-2 border-border bg-muted p-4 font-mono text-[0.9rem] leading-relaxed dark:bg-muted/40 print:block print:whitespace-pre-wrap print:break-words",
          wrap
            ? "whitespace-pre-wrap [overflow-wrap:anywhere]"
            : "overflow-x-auto whitespace-pre",
        )}
      >
        {text}
      </pre>
    </div>
  );
}
