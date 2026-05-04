/**
 * Thin wrappers over IVRE's Web API (mounted at ``/cgi/`` by ``ivre
 * httpd``). All routes return plain JSON or NDJSON since the May
 * 2026 JSONP removal; consumers should use ``fetch()`` and
 * ``Response.json()`` / line splitting.
 *
 * Higher-level callers should prefer the ``useView``, ``useTop``,
 * ``useCoordinates`` React Query hooks below; these wrap the raw
 * functions with caching and refetch behaviour.
 */

import {
  useQuery,
  type UseQueryOptions,
  type UseQueryResult,
} from "@tanstack/react-query";

/** Root of the IVRE Web API. Vite proxies ``/cgi`` to a backend in
 *  development; in production the bundle is served from the same
 *  origin as the API. */
export const CGI_ROOT = "/cgi";

/** Build a query string from a flat record. ``undefined`` values are
 *  skipped; everything else is coerced via ``String()``. */
function qs(params: Record<string, string | number | undefined>): string {
  const entries = Object.entries(params).filter(
    ([, v]) => v !== undefined && v !== "",
  );
  if (entries.length === 0) return "";
  return (
    "?" +
    entries
      .map(
        ([k, v]) =>
          `${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`,
      )
      .join("&")
  );
}

/* ------------------------------------------------------------------ */
/* Types                                                              */
/* ------------------------------------------------------------------ */

export interface HostRecord {
  addr: string;
  status?: string;
  /** Provenance string. Active scan documents (``db.nmap``)
   *  store it as a single string; the view (``db.view``)
   *  merges multiple scan sources into an array. Consumers
   *  must accept either form. */
  source?: string | string[];
  starttime?: string | number;
  endtime?: string | number;
  infos?: {
    country_code?: string;
    country_name?: string;
    as_num?: number;
    as_name?: string;
    location?: { coordinates?: [number, number] };
  };
  hostnames?: Array<{
    name: string;
    type?: string;
    domains?: string[];
  }>;
  categories?: string[];
  tags?: Array<{
    value: string;
    type?: string;
    info?: string[];
  }>;
  ports?: Array<{
    protocol: string;
    port: number;
    state_state?: string;
    service_name?: string;
    service_product?: string;
    service_version?: string;
    scripts?: Array<{ id: string; output?: string; [k: string]: unknown }>;
    [k: string]: unknown;
  }>;
  [k: string]: unknown;
}

export interface TopValue {
  /** Either a primitive label or a tuple. See ``field-mapper.ts``
   *  for the cases. */
  label: string | number | (string | number)[];
  value: number;
}

export interface CoordinatesResponse {
  type: "GeometryCollection";
  geometries: Array<{
    type: "Point";
    coordinates: [number, number];
    properties?: { count?: number };
  }>;
}

/** A passive-recon record as served by ``GET /cgi/passive``.
 *
 *  ``schema_version``, ``recontype``, ``value``, ``firstseen``,
 *  ``lastseen`` and ``count`` are always present; everything else
 *  depends on the kind of observation (DNS answer, HTTP header,
 *  TLS cert, JA3, …). ``firstseen`` / ``lastseen`` come back as
 *  Unix timestamps (number of seconds) by default and as ISO-ish
 *  strings when ``datesasstrings=1`` was passed. */
export interface PassiveRecord {
  schema_version: number;
  recontype: string;
  value: string;
  count: number;
  firstseen: number | string;
  lastseen: number | string;
  /** Set whenever the observation is attached to a single host
   *  (most records). Absent for DNS CNAME/MX/NS/PTR records,
   *  where ``value`` is the queried name. */
  addr?: string;
  /** Set when the record is not keyed on ``addr`` — e.g. DNS
   *  CNAME answers where ``targetval`` is the canonical name. */
  targetval?: string;
  sensor?: string;
  port?: number;
  /** Sub-type string scoping the recontype; semantics depend on
   *  the recontype. For ``DNS_ANSWER`` records the backend already
   *  splits the historical ``"<TYPE>-<server>-<sport>"`` source
   *  into a clean ``source`` plus an ``rrtype`` field (see below). */
  source?: string;
  /** Set on ``DNS_ANSWER`` records: ``"A"``, ``"AAAA"``,
   *  ``"CNAME"``, ``"PTR"``, ``"MX"``, ``"NS"``, ``"SOA"``,
   *  ``"TXT"``, … */
  rrtype?: string;
  /** Heterogeneous extra metadata: ``infos.domain`` /
   *  ``domaintarget`` / ``san`` are arrays of strings;
   *  ``infos.subject_text`` / ``issuer_text`` / ``sha1`` /
   *  ``sha256`` etc. are scalars; ``infos.not_before`` /
   *  ``not_after`` follow the same date-coercion rule as
   *  ``firstseen`` / ``lastseen``. */
  infos?: { [k: string]: unknown };
  [k: string]: unknown;
}

/* ------------------------------------------------------------------ */
/* Raw fetchers                                                       */
/* ------------------------------------------------------------------ */

export interface ListParams {
  q?: string;
  limit?: number;
  skip?: number;
  ipsasnumbers?: boolean;
  datesasstrings?: boolean;
}

/** Parse a streamed NDJSON body into an array of records. Tolerates
 *  trailing newlines and empty lines; throws on malformed JSON. */
async function parseNdjson(response: Response): Promise<HostRecord[]> {
  const text = await response.text();
  const out: HostRecord[] = [];
  for (const line of text.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    out.push(JSON.parse(trimmed));
  }
  return out;
}

async function ensureOk(response: Response, label: string): Promise<void> {
  if (!response.ok) {
    throw new Error(
      `${label} failed: ${response.status} ${response.statusText}`,
    );
  }
}

/** Fetch a list of host records from a section's listEndpoint as
 *  NDJSON. ``listEndpoint`` is the path under ``/cgi/`` (e.g.
 *  ``/view``, ``/scans``). */
export async function fetchHosts(
  listEndpoint: string,
  params: ListParams = {},
): Promise<HostRecord[]> {
  const url =
    CGI_ROOT +
    listEndpoint +
    qs({
      q: params.q,
      limit: params.limit,
      skip: params.skip,
      ipsasnumbers: params.ipsasnumbers ? 1 : undefined,
      datesasstrings: params.datesasstrings ? 1 : undefined,
      format: "ndjson",
    });
  const response = await fetch(url, { credentials: "same-origin" });
  await ensureOk(response, `GET ${url}`);
  return parseNdjson(response);
}

/** Fetch the count of records matching a filter. */
export async function fetchCount(
  countEndpoint: string,
  params: { q?: string } = {},
): Promise<number> {
  const url = CGI_ROOT + countEndpoint + qs({ q: params.q });
  const response = await fetch(url, { credentials: "same-origin" });
  await ensureOk(response, `GET ${url}`);
  const text = await response.text();
  return Number.parseInt(text.trim(), 10);
}

/** Fetch top-N values for a given field. Returns the array of
 *  ``{label, value}`` rows from
 *  ``/cgi/<purpose>/top/<field>[:<limit>]``. */
export async function fetchTop(
  topEndpoint: string,
  field: string,
  params: { q?: string; limit?: number } = {},
): Promise<TopValue[]> {
  // The IVRE backend already accepts ``<field>:<N>`` syntax for the
  // top-N limit; we use that when ``limit`` is given so the URL
  // mirrors the legacy AngularJS UI.
  const fieldPath =
    params.limit !== undefined ? `${field}:${params.limit}` : field;
  const url =
    CGI_ROOT +
    topEndpoint +
    "/" +
    fieldPath.split("/").map(encodeURIComponent).join("/") +
    qs({ q: params.q });
  const response = await fetch(url, { credentials: "same-origin" });
  await ensureOk(response, `GET ${url}`);
  return (await response.json()) as TopValue[];
}

/** Fetch a list of passive-recon records as NDJSON. ``firstseen``
 *  / ``lastseen`` come back as Unix-epoch numbers; the caller is
 *  expected to convert them to ``Date`` for display. */
export async function fetchPassiveRecords(
  listEndpoint: string,
  params: ListParams = {},
): Promise<PassiveRecord[]> {
  const url =
    CGI_ROOT +
    listEndpoint +
    qs({
      q: params.q,
      limit: params.limit,
      skip: params.skip,
      ipsasnumbers: params.ipsasnumbers ? 1 : undefined,
      datesasstrings: params.datesasstrings ? 1 : undefined,
      format: "ndjson",
    });
  const response = await fetch(url, { credentials: "same-origin" });
  await ensureOk(response, `GET ${url}`);
  const text = await response.text();
  const out: PassiveRecord[] = [];
  for (const line of text.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    out.push(JSON.parse(trimmed));
  }
  return out;
}

/** Fetch the GeoJSON GeometryCollection for the world-map widget. */
export async function fetchCoordinates(
  mapEndpoint: string,
  params: { q?: string } = {},
): Promise<CoordinatesResponse> {
  const url =
    CGI_ROOT + mapEndpoint + qs({ q: params.q, ipsasnumbers: 1 });
  const response = await fetch(url, { credentials: "same-origin" });
  await ensureOk(response, `GET ${url}`);
  return (await response.json()) as CoordinatesResponse;
}

/** A merged DNS pseudo-record returned by ``GET /cgi/dns``. The
 *  endpoint folds together every observation of a given
 *  ``(name, addr)`` pair across the active scan database
 *  (``db.nmap``) and the passive observation database
 *  (``db.passive``). ``count`` is the sum of the per-source
 *  counts; ``types`` and ``sources`` are unions across both
 *  backends; ``firstseen`` / ``lastseen`` extend the union of
 *  the contributing intervals. */
export interface DnsRecord {
  name: string;
  addr: string;
  count: number;
  firstseen: number | string;
  lastseen: number | string;
  /** Hostname types that contributed to this row. Active
   *  scans typically supply ``"A"`` / ``"AAAA"`` / ``"PTR"`` /
   *  ``"user"`` / ``"ssl-cert-subject"`` etc; passive supplies
   *  the DNS rrtype prefix (``"A"``, ``"AAAA"``, ``"CNAME"``,
   *  ...). */
  types: string[];
  /** Where the observations came from: scan ``source`` strings
   *  on the active side, ``sensor`` names on the passive side. */
  sources: string[];
}

/** Fetch the merged DNS pseudo-record list as JSON. */
export async function fetchDnsRecords(
  params: ListParams = {},
): Promise<DnsRecord[]> {
  const url =
    CGI_ROOT +
    "/dns" +
    qs({
      q: params.q,
      limit: params.limit,
      skip: params.skip,
      datesasstrings: params.datesasstrings ? 1 : undefined,
      format: "json",
    });
  const response = await fetch(url, { credentials: "same-origin" });
  await ensureOk(response, `GET ${url}`);
  return (await response.json()) as DnsRecord[];
}

/* ------------------------------------------------------------------ */
/* RIR records                                                        */
/* ------------------------------------------------------------------ */

/** Common provenance fields every RIR record carries. The dump
 *  format is RPSL: keys may appear in any order and many are
 *  optional. We type the well-known ones explicitly and fall
 *  back to ``unknown`` for the rest via the index signature. */
interface RirRecordCommon {
  schema_version?: number;
  source_file?: string;
  source_hash?: string;
  source?: string;
  country?: string;
  descr?: string | string[];
  org?: string | string[];
  remarks?: string | string[];
  notify?: string | string[];
  /** Anything else the source dump carried (``mnt-by``, ``status``,
   *  ``language``, ``created``, ``last-modified``, ...). The card
   *  renders these via a generic key/value table. */
  [key: string]: unknown;
}

/** ``inet[6]num`` record: a contiguous IP range with an optional
 *  network name and free-form description. ``size`` (number of
 *  addresses, inclusive) is added at insert time on schema v2;
 *  emitted as a JSON ``number`` for the common case and as a
 *  decimal-string when the value exceeds JS safe-integer range
 *  (IPv6 ranges wider than /74). */
export interface RirInetNum extends RirRecordCommon {
  start: string;
  stop: string;
  netname?: string;
  size?: number | string;
}

/** ``aut-num`` record: an Autonomous System number. Note the
 *  hyphenated keys — accessed via bracket syntax in TypeScript
 *  (``record["aut-num"]``, ``record["as-name"]``) because the
 *  underlying RPSL dump preserves the hyphens. */
export interface RirAutNum extends RirRecordCommon {
  "aut-num": number;
  "as-name"?: string;
}

/** Discriminated union: every record from ``/cgi/rir`` is one
 *  family or the other. Discriminate by the presence of either
 *  ``start`` (inet[6]num) or ``aut-num`` (AS records). */
export type RirRecord = RirInetNum | RirAutNum;

/** Type-guard: ``true`` for inet[6]num records. */
export function isRirInetNum(rec: RirRecord): rec is RirInetNum {
  return typeof (rec as RirInetNum).start === "string";
}

/** Type-guard: ``true`` for ``aut-num`` records. */
export function isRirAutNum(rec: RirRecord): rec is RirAutNum {
  return typeof (rec as RirAutNum)["aut-num"] === "number";
}

/** Fetch the RIR record list. The backend default sort is
 *  narrowest-range first; pass an explicit ``sortby=`` in the
 *  query string to override. */
export async function fetchRirRecords(
  params: ListParams = {},
): Promise<RirRecord[]> {
  const url =
    CGI_ROOT +
    "/rir" +
    qs({
      q: params.q,
      limit: params.limit,
      skip: params.skip,
      format: "json",
    });
  const response = await fetch(url, { credentials: "same-origin" });
  await ensureOk(response, `GET ${url}`);
  return (await response.json()) as RirRecord[];
}

/* ------------------------------------------------------------------ */
/* Flow records (graph)                                               */
/* ------------------------------------------------------------------ */

/** A node in the flow graph (one host). ``data`` carries the
 *  identifying address plus first/last-seen timestamps. ``x`` /
 *  ``y`` are random initial coordinates the backend assigns
 *  per-response; the React layer uses them as a starting layout
 *  hint and lets cytoscape's force layout converge from there. */
export interface FlowNode {
  id: string;
  label: string;
  labels: string[];
  x: number;
  y: number;
  data: {
    addr: string;
    firstseen?: string | number;
    lastseen?: string | number;
    [k: string]: unknown;
  };
}

/** An edge in the flow graph. ``label`` is one of:
 *
 *  - ``"<proto>/<dport>"`` (default mode, e.g. ``"tcp/443"``)
 *  - ``"MERGED_FLOWS"`` (``flow_map`` mode — collapsed per
 *    src/dst pair; ``data.flows`` carries the list of
 *    contributing ``(proto, dport)`` tuples)
 *  - ``"TALK"`` (``talk_map`` mode — collapsed per src/dst
 *    pair; ``data.flows = ["TALK"]``)
 *
 *  See ``ivre/db/__init__.py`` ``_edge2json_*`` helpers for the
 *  authoritative shapes. */
export interface FlowEdge {
  id: string;
  label: string;
  labels: string[];
  source: string;
  target: string;
  data: {
    proto?: string;
    dport?: number;
    sports?: number[];
    type?: number;
    codes?: number[];
    count?: number;
    cspkts?: number;
    csbytes?: number;
    scpkts?: number;
    scbytes?: number;
    firstseen?: string | number;
    lastseen?: string | number;
    addr_src?: string;
    addr_dst?: string;
    flows?: Array<[string, number] | string>;
    meta?: { times?: Array<{ start: string | number; duration: number }> };
    [k: string]: unknown;
  };
}

/** Wire shape of ``GET /cgi/flows`` (default action). */
export interface FlowGraph {
  nodes: FlowNode[];
  edges: FlowEdge[];
}

/** Wire shape of ``GET /cgi/flows`` with ``q.count = true``. */
export interface FlowCounts {
  clients: number;
  servers: number;
  flows: number;
}

/** Edge-aggregation modes the backend supports.
 *
 *  - ``default``: each unique flow document is a separate edge.
 *  - ``flow_map``: edges collapse per ``(src, dst)``;
 *    ``data.flows`` carries every contributing ``(proto, dport)``.
 *  - ``talk_map``: edges collapse per ``(src, dst)`` ignoring
 *    everything below — a "who talks to whom" overview.
 */
export type FlowMode = "default" | "flow_map" | "talk_map";

/** The JSON-encoded ``q=`` parameter the ``/cgi/flows`` route
 *  consumes. ``nodes`` and ``edges`` are arrays of
 *  ``flow.Query``-grammar filter strings (see the legacy
 *  AngularJS UI's "Node filters" / "Edge filters" textareas).
 *  ``before`` / ``after`` are ``"YYYY-MM-DD HH:MM"`` strings. */
export interface FlowQuery {
  nodes?: string[];
  edges?: string[];
  limit?: number;
  skip?: number;
  mode?: FlowMode;
  count?: boolean;
  orderby?: "src" | "dst" | "flow" | null;
  timeline?: boolean;
  before?: string;
  after?: string;
}

/** Host-details payload returned by
 *  ``GET /cgi/flows?action=details&q={type:"node",id:"<addr>"}``. */
export interface FlowHostDetails {
  elt: { addr: string; firstseen?: string; lastseen?: string };
  in_flows: Array<[string, number] | string>;
  out_flows: Array<[string, number] | string>;
  clients: string[];
  servers: string[];
}

/** Edge-details payload returned by
 *  ``GET /cgi/flows?action=details&q={type:"edge",id:"<oid>"}``. */
export interface FlowEdgeDetails {
  elt: FlowEdge["data"];
  meta?: Record<string, Record<string, unknown>>;
}

/** Build the URL for any ``/cgi/flows`` call. The route accepts
 *  one parameter, ``q=``, JSON-encoded. ``action=details`` is
 *  passed as a separate URL parameter, not folded into ``q``. */
function flowUrl(query: object, action?: "details"): string {
  const params: Record<string, string> = {
    q: JSON.stringify(query),
  };
  if (action !== undefined) params.action = action;
  return (
    CGI_ROOT +
    "/flows?" +
    Object.entries(params)
      .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
      .join("&")
  );
}

export async function fetchFlowGraph(query: FlowQuery): Promise<FlowGraph> {
  const url = flowUrl({ ...query, count: false });
  const response = await fetch(url, { credentials: "same-origin" });
  await ensureOk(response, `GET /cgi/flows`);
  return (await response.json()) as FlowGraph;
}

export async function fetchFlowCounts(query: FlowQuery): Promise<FlowCounts> {
  const url = flowUrl({ ...query, count: true });
  const response = await fetch(url, { credentials: "same-origin" });
  await ensureOk(response, `GET /cgi/flows (count)`);
  return (await response.json()) as FlowCounts;
}

export async function fetchFlowDetails(
  type: "node" | "edge",
  id: string,
  query: FlowQuery = {},
): Promise<FlowHostDetails | FlowEdgeDetails> {
  const url = flowUrl({ ...query, type, id }, "details");
  const response = await fetch(url, { credentials: "same-origin" });
  await ensureOk(response, `GET /cgi/flows (details)`);
  return (await response.json()) as FlowHostDetails | FlowEdgeDetails;
}

/* ------------------------------------------------------------------ */
/* React Query hooks                                                  */
/* ------------------------------------------------------------------ */

type HookOptions<T> = Omit<UseQueryOptions<T>, "queryKey" | "queryFn">;

export function useHosts(
  listEndpoint: string | undefined,
  params: ListParams,
  options?: HookOptions<HostRecord[]>,
): UseQueryResult<HostRecord[]> {
  return useQuery<HostRecord[]>({
    queryKey: ["hosts", listEndpoint, params],
    queryFn: () => fetchHosts(listEndpoint as string, params),
    enabled: Boolean(listEndpoint),
    ...options,
  });
}

export function usePassiveRecords(
  listEndpoint: string | undefined,
  params: ListParams,
  options?: HookOptions<PassiveRecord[]>,
): UseQueryResult<PassiveRecord[]> {
  return useQuery<PassiveRecord[]>({
    queryKey: ["passive", listEndpoint, params],
    queryFn: () => fetchPassiveRecords(listEndpoint as string, params),
    enabled: Boolean(listEndpoint),
    ...options,
  });
}

export function useCount(
  countEndpoint: string | undefined,
  params: { q?: string },
  options?: HookOptions<number>,
): UseQueryResult<number> {
  return useQuery<number>({
    queryKey: ["count", countEndpoint, params],
    queryFn: () => fetchCount(countEndpoint as string, params),
    enabled: Boolean(countEndpoint),
    ...options,
  });
}

export function useTop(
  topEndpoint: string | undefined,
  field: string,
  params: { q?: string; limit?: number },
  options?: HookOptions<TopValue[]>,
): UseQueryResult<TopValue[]> {
  return useQuery<TopValue[]>({
    queryKey: ["top", topEndpoint, field, params],
    queryFn: () => fetchTop(topEndpoint as string, field, params),
    enabled: Boolean(topEndpoint && field),
    ...options,
  });
}

export function useCoordinates(
  mapEndpoint: string | undefined,
  params: { q?: string },
  options?: HookOptions<CoordinatesResponse>,
): UseQueryResult<CoordinatesResponse> {
  return useQuery<CoordinatesResponse>({
    queryKey: ["coordinates", mapEndpoint, params],
    queryFn: () => fetchCoordinates(mapEndpoint as string, params),
    enabled: Boolean(mapEndpoint),
    ...options,
  });
}

export function useDnsRecords(
  params: ListParams,
  options?: HookOptions<DnsRecord[]>,
): UseQueryResult<DnsRecord[]> {
  return useQuery<DnsRecord[]>({
    queryKey: ["dns", params],
    queryFn: () => fetchDnsRecords(params),
    ...options,
  });
}

export function useRirRecords(
  params: ListParams,
  options?: HookOptions<RirRecord[]>,
): UseQueryResult<RirRecord[]> {
  return useQuery<RirRecord[]>({
    queryKey: ["rir", params],
    queryFn: () => fetchRirRecords(params),
    ...options,
  });
}

export function useFlowGraph(
  query: FlowQuery,
  options?: HookOptions<FlowGraph>,
): UseQueryResult<FlowGraph> {
  return useQuery<FlowGraph>({
    queryKey: ["flow", "graph", query],
    queryFn: () => fetchFlowGraph(query),
    ...options,
  });
}

export function useFlowCounts(
  query: FlowQuery,
  options?: HookOptions<FlowCounts>,
): UseQueryResult<FlowCounts> {
  return useQuery<FlowCounts>({
    queryKey: ["flow", "counts", query],
    queryFn: () => fetchFlowCounts(query),
    ...options,
  });
}

export function useFlowDetails(
  type: "node" | "edge" | undefined,
  id: string | undefined,
  options?: HookOptions<FlowHostDetails | FlowEdgeDetails>,
): UseQueryResult<FlowHostDetails | FlowEdgeDetails> {
  return useQuery<FlowHostDetails | FlowEdgeDetails>({
    queryKey: ["flow", "details", type, id],
    queryFn: () => fetchFlowDetails(type as "node" | "edge", id as string),
    enabled: Boolean(type && id),
    ...options,
  });
}
