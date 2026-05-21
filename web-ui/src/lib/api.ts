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
  useMutation,
  useQuery,
  useQueryClient,
  type UseMutationResult,
  type UseQueryResult,
} from "@tanstack/react-query";

import { gatedEnabled, type HookOptions } from "./api-internals";

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
 *  ``/view``, ``/scans``).
 *
 *  ``signal`` is forwarded to ``fetch()`` so React Query (or any
 *  other caller) can abort the request when the query becomes
 *  inactive (filter change, component unmount). Without this the
 *  underlying HTTP request keeps running on the server even after
 *  the cache observer goes away, piling up obsolete work on the
 *  single uwsgi worker. */
export async function fetchHosts(
  listEndpoint: string,
  params: ListParams = {},
  signal?: AbortSignal,
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
  const response = await fetch(url, { credentials: "same-origin", signal });
  await ensureOk(response, `GET ${url}`);
  return parseNdjson(response);
}

/** Fetch the count of records matching a filter. */
export async function fetchCount(
  countEndpoint: string,
  params: { q?: string } = {},
  signal?: AbortSignal,
): Promise<number> {
  const url = CGI_ROOT + countEndpoint + qs({ q: params.q });
  const response = await fetch(url, { credentials: "same-origin", signal });
  await ensureOk(response, `GET ${url}`);
  const text = await response.text();
  // Validate strictly: the body MUST be a bare non-negative
  // decimal integer (no sign, no decimal point, no trailing
  // characters). ``Number.parseInt`` would accept partial
  // numerics like ``"12abc"`` -> ``12`` or ``"1.5"`` -> ``1``
  // and silently turn a malformed body into a plausible-looking
  // count. Anything else — empty 204, HTML error page, JSON
  // envelope, banner-appended response — fails this check and
  // lands the query in ``error`` state so callers fall back to
  // the loaded-only headline rather than displaying ``NaN`` or
  // a truncated number.
  const trimmed = text.trim();
  if (!/^\d+$/.test(trimmed)) {
    throw new Error(
      `GET ${url} returned non-numeric body: ${text.slice(0, 64)}`,
    );
  }
  return Number.parseInt(trimmed, 10);
}

/** Fetch top-N values for a given field. Returns the array of
 *  ``{label, value}`` rows from
 *  ``/cgi/<purpose>/top/<field>[:<limit>]``. */
export async function fetchTop(
  topEndpoint: string,
  field: string,
  params: { q?: string; limit?: number } = {},
  signal?: AbortSignal,
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
  const response = await fetch(url, { credentials: "same-origin", signal });
  await ensureOk(response, `GET ${url}`);
  return (await response.json()) as TopValue[];
}

/** Fetch a list of passive-recon records as NDJSON. ``firstseen``
 *  / ``lastseen`` come back as Unix-epoch numbers; the caller is
 *  expected to convert them to ``Date`` for display. */
export async function fetchPassiveRecords(
  listEndpoint: string,
  params: ListParams = {},
  signal?: AbortSignal,
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
  const response = await fetch(url, { credentials: "same-origin", signal });
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
  signal?: AbortSignal,
): Promise<CoordinatesResponse> {
  const url =
    CGI_ROOT + mapEndpoint + qs({ q: params.q, ipsasnumbers: 1 });
  const response = await fetch(url, { credentials: "same-origin", signal });
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
  signal?: AbortSignal,
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
  const response = await fetch(url, { credentials: "same-origin", signal });
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
  signal?: AbortSignal,
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
  const response = await fetch(url, { credentials: "same-origin", signal });
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

export async function fetchFlowGraph(
  query: FlowQuery,
  signal?: AbortSignal,
): Promise<FlowGraph> {
  const url = flowUrl({ ...query, count: false });
  const response = await fetch(url, { credentials: "same-origin", signal });
  await ensureOk(response, `GET /cgi/flows`);
  return (await response.json()) as FlowGraph;
}

export async function fetchFlowCounts(
  query: FlowQuery,
  signal?: AbortSignal,
): Promise<FlowCounts> {
  const url = flowUrl({ ...query, count: true });
  const response = await fetch(url, { credentials: "same-origin", signal });
  await ensureOk(response, `GET /cgi/flows (count)`);
  return (await response.json()) as FlowCounts;
}

export async function fetchFlowDetails(
  type: "node" | "edge",
  id: string,
  query: FlowQuery = {},
  signal?: AbortSignal,
): Promise<FlowHostDetails | FlowEdgeDetails> {
  const url = flowUrl({ ...query, type, id }, "details");
  const response = await fetch(url, { credentials: "same-origin", signal });
  await ensureOk(response, `GET /cgi/flows (details)`);
  return (await response.json()) as FlowHostDetails | FlowEdgeDetails;
}

/* ------------------------------------------------------------------ */
/* React Query hooks                                                  */
/* ------------------------------------------------------------------ */

// ``HookOptions<T>`` and the ``gatedEnabled`` helper used by every
// precondition'd hook below live in ``./api-internals``: they are
// implementation details, not part of the public hook surface, and
// the separate file is the structural signal that says so. See
// that file's doc block for the helper's contract and the
// rationale behind it.

// Every ``queryFn`` below destructures the ``{ signal }`` React
// Query passes in and forwards it to the raw fetcher, which in turn
// forwards it to ``fetch()``. Without this, when the query becomes
// inactive (filter change, component unmount, ``cancelQueries``)
// React Query stops subscribing to the result but the underlying
// HTTP request keeps running to completion and the server keeps
// doing the work — visibly slow on rapid filter edits against a
// single-worker uwsgi deployment.

export function useHosts(
  listEndpoint: string | undefined,
  params: ListParams,
  options?: HookOptions<HostRecord[]>,
): UseQueryResult<HostRecord[]> {
  return useQuery<HostRecord[]>({
    queryKey: ["hosts", listEndpoint, params],
    queryFn: ({ signal }) =>
      fetchHosts(listEndpoint as string, params, signal),
    ...options,
    enabled: gatedEnabled(Boolean(listEndpoint), options),
  });
}

export function usePassiveRecords(
  listEndpoint: string | undefined,
  params: ListParams,
  options?: HookOptions<PassiveRecord[]>,
): UseQueryResult<PassiveRecord[]> {
  return useQuery<PassiveRecord[]>({
    queryKey: ["passive", listEndpoint, params],
    queryFn: ({ signal }) =>
      fetchPassiveRecords(listEndpoint as string, params, signal),
    ...options,
    enabled: gatedEnabled(Boolean(listEndpoint), options),
  });
}

export function useCount(
  countEndpoint: string | undefined,
  params: { q?: string },
  options?: HookOptions<number>,
): UseQueryResult<number> {
  return useQuery<number>({
    queryKey: ["count", countEndpoint, params],
    queryFn: ({ signal }) =>
      fetchCount(countEndpoint as string, params, signal),
    ...options,
    enabled: gatedEnabled(Boolean(countEndpoint), options),
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
    queryFn: ({ signal }) =>
      fetchTop(topEndpoint as string, field, params, signal),
    ...options,
    enabled: gatedEnabled(Boolean(topEndpoint && field), options),
  });
}

export function useCoordinates(
  mapEndpoint: string | undefined,
  params: { q?: string },
  options?: HookOptions<CoordinatesResponse>,
): UseQueryResult<CoordinatesResponse> {
  return useQuery<CoordinatesResponse>({
    queryKey: ["coordinates", mapEndpoint, params],
    queryFn: ({ signal }) =>
      fetchCoordinates(mapEndpoint as string, params, signal),
    ...options,
    enabled: gatedEnabled(Boolean(mapEndpoint), options),
  });
}

export function useDnsRecords(
  params: ListParams,
  options?: HookOptions<DnsRecord[]>,
): UseQueryResult<DnsRecord[]> {
  return useQuery<DnsRecord[]>({
    queryKey: ["dns", params],
    queryFn: ({ signal }) => fetchDnsRecords(params, signal),
    ...options,
  });
}

export function useRirRecords(
  params: ListParams,
  options?: HookOptions<RirRecord[]>,
): UseQueryResult<RirRecord[]> {
  return useQuery<RirRecord[]>({
    queryKey: ["rir", params],
    queryFn: ({ signal }) => fetchRirRecords(params, signal),
    ...options,
  });
}

export function useFlowGraph(
  query: FlowQuery,
  options?: HookOptions<FlowGraph>,
): UseQueryResult<FlowGraph> {
  return useQuery<FlowGraph>({
    queryKey: ["flow", "graph", query],
    queryFn: ({ signal }) => fetchFlowGraph(query, signal),
    ...options,
  });
}

export function useFlowCounts(
  query: FlowQuery,
  options?: HookOptions<FlowCounts>,
): UseQueryResult<FlowCounts> {
  return useQuery<FlowCounts>({
    queryKey: ["flow", "counts", query],
    queryFn: ({ signal }) => fetchFlowCounts(query, signal),
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
    queryFn: ({ signal }) =>
      fetchFlowDetails(type as "node" | "edge", id as string, {}, signal),
    ...options,
    enabled: gatedEnabled(Boolean(type && id), options),
  });
}

/* ------------------------------------------------------------------ */
/* Notes                                                              */
/* ------------------------------------------------------------------ */

/** Single persisted note as returned by ``GET /cgi/notes/<type>/<key>``.
 *  ``entity_key`` is in the caller-facing form (printable IP string
 *  for the ``host`` entity type). */
export interface Note {
  entity_type: string;
  entity_key: string;
  body: string;
  revision: number;
  created_at: string;
  created_by: string;
  updated_at: string;
  updated_by: string;
}

/** Discriminated outcome of a single-note fetch.
 *
 * * ``found`` -- the note exists.
 * * ``absent`` -- the route returned 404; no note has been written
 *   for this entity yet.
 * * ``unavailable`` -- the route returned 501; the configured
 *   backend does not implement the notes purpose (any non-MongoDB
 *   deployment today).  Consumers typically hide the notes UI in
 *   this case rather than surface a warning.
 *
 * Other HTTP failures (network errors, 5xx, malformed JSON) throw
 * and reach the caller via React Query's ``isError`` path.
 */
export type HostNoteResult =
  | { kind: "found"; note: Note }
  | { kind: "absent" }
  | { kind: "unavailable" };

/** Fetch the note for a host (caller-facing IP string). Returns a
 *  discriminated union so the four UI states (found / absent /
 *  unavailable / error) are explicit at the call site. */
export async function fetchHostNote(
  addr: string,
  signal?: AbortSignal,
): Promise<HostNoteResult> {
  const url = `${CGI_ROOT}/notes/host/${encodeURIComponent(addr)}`;
  const response = await fetch(url, { credentials: "same-origin", signal });
  if (response.status === 404) {
    return { kind: "absent" };
  }
  if (response.status === 501) {
    return { kind: "unavailable" };
  }
  await ensureOk(response, `GET ${url}`);
  const note = (await response.json()) as Note;
  return { kind: "found", note };
}

/** React Query hook around :func:`fetchHostNote`.  Gated on
 *  ``Boolean(addr)`` so a missing addr keeps the query idle (no
 *  background fetch for an empty key). */
export function useHostNote(
  addr: string | undefined,
  options?: HookOptions<HostNoteResult>,
): UseQueryResult<HostNoteResult> {
  return useQuery<HostNoteResult>({
    queryKey: ["notes", "host", addr],
    queryFn: ({ signal }) => fetchHostNote(addr as string, signal),
    ...options,
    enabled: gatedEnabled(Boolean(addr), options),
  });
}

/** One entry of the revision history returned by
 *  ``GET /cgi/notes/<type>/<key>/revisions``.  Newest revision
 *  first.  The route strips ``entity_type`` / ``entity_key`` from
 *  each entry (the caller knows them already). */
export interface NoteRevision {
  revision: number;
  body: string;
  created_at: string;
  created_by: string;
}

/** Save-mode discriminator for :func:`saveHostNote`.
 *
 * * ``create`` -- ``If-None-Match: *``: PUT only succeeds when
 *   no note exists yet.  Used by the "Add note" affordance on
 *   the empty state.
 * * ``update`` -- ``If-Match: <expectedRevision>``: optimistic
 *   concurrency update.  The expected revision is the one the
 *   operator started editing from; the storage layer rejects
 *   the write if another caller has bumped the revision in
 *   between.
 */
export type SaveHostNoteMode =
  | { kind: "create" }
  | { kind: "update"; expectedRevision: number };

/** Discriminated outcome of :func:`saveHostNote`.
 *
 * * ``saved`` -- the write succeeded; carries the persisted note.
 * * ``conflict`` -- the route returned 409.  ``message`` is the
 *   server's abort-message text body (the storage-layer
 *   ``NoteConcurrencyError`` -- "stored revision N does not
 *   match expected=M..." -- or ``NoteAlreadyExists`` --
 *   "note already exists for ..." -- distinction lives in
 *   that text).  Callers re-fetch via
 *   :func:`useHostNote`'s ``refetch`` (or
 *   ``queryClient.invalidateQueries``) to repopulate the
 *   cache with the current server-side note before
 *   retrying.
 * * ``unauthorized`` -- the route returned 401 (write paths
 *   require an authenticated user).
 * * ``too_large`` -- the route returned 413 (body exceeds
 *   ``WEB_HOST_NOTES_MAX_BYTES``).
 * * ``not_found`` -- the route returned 404 (only reachable on
 *   ``update`` mode: the note was deleted between load and
 *   save).  Empty-state recovery: surface "the note was
 *   deleted; recreate?" to the operator.
 *
 * Other HTTP failures throw and reach the caller via React
 * Query's ``isError`` path on the surrounding mutation.
 */
export type SaveHostNoteResult =
  | { kind: "saved"; note: Note }
  | { kind: "conflict"; message: string }
  | { kind: "unauthorized" }
  | { kind: "too_large" }
  | { kind: "not_found" };

/** Persist a host note.  See :type:`SaveHostNoteMode` for the
 *  two write modes; :type:`SaveHostNoteResult` for the
 *  caller-visible outcomes. */
export async function saveHostNote(
  addr: string,
  body: string,
  mode: SaveHostNoteMode,
  signal?: AbortSignal,
): Promise<SaveHostNoteResult> {
  const url = `${CGI_ROOT}/notes/host/${encodeURIComponent(addr)}`;
  // Translate the discriminated save-mode into the HTTP
  // precondition headers documented on ``PUT /cgi/notes/...``.
  const headers: Record<string, string> = {
    "Content-Type": "text/markdown; charset=utf-8",
  };
  if (mode.kind === "create") {
    headers["If-None-Match"] = "*";
  } else {
    headers["If-Match"] = String(mode.expectedRevision);
  }
  const response = await fetch(url, {
    method: "PUT",
    credentials: "same-origin",
    headers,
    body,
    signal,
  });
  if (response.status === 401) return { kind: "unauthorized" };
  if (response.status === 404) return { kind: "not_found" };
  if (response.status === 409) {
    // The route returns the abort-message text body; surface
    // it so the caller can decide whether to show
    // "concurrent edit" or "note already exists" prose
    // (the storage-layer ``NoteConcurrencyError`` /
    // ``NoteAlreadyExists`` distinction lives in that text).
    const message = await response.text().catch(() => "Conflict");
    return { kind: "conflict", message };
  }
  if (response.status === 413) return { kind: "too_large" };
  await ensureOk(response, `PUT ${url}`);
  const note = (await response.json()) as Note;
  return { kind: "saved", note };
}

/** Delete a host note (and its revision history).  Returns
 *  ``true`` when a note existed and was removed, ``false`` when
 *  the route returned 404 (no note to delete).  Other failures
 *  throw. */
export async function deleteHostNote(
  addr: string,
  signal?: AbortSignal,
): Promise<boolean> {
  const url = `${CGI_ROOT}/notes/host/${encodeURIComponent(addr)}`;
  const response = await fetch(url, {
    method: "DELETE",
    credentials: "same-origin",
    signal,
  });
  if (response.status === 404) return false;
  if (response.status === 401) {
    throw new Error("Authentication required to delete notes");
  }
  await ensureOk(response, `DELETE ${url}`);
  return true;
}

/** Fetch the full revision history of a host note (newest
 *  first).  Returns an empty array when no note exists for the
 *  host -- the route is read-only and does not 404 on missing
 *  entities (it surfaces the same shape as for an entity with
 *  zero revisions). */
export async function fetchHostNoteRevisions(
  addr: string,
  signal?: AbortSignal,
): Promise<NoteRevision[]> {
  const url = `${CGI_ROOT}/notes/host/${encodeURIComponent(addr)}/revisions`;
  const response = await fetch(url, { credentials: "same-origin", signal });
  await ensureOk(response, `GET ${url}`);
  return (await response.json()) as NoteRevision[];
}

/** React Query hook around :func:`fetchHostNoteRevisions`.
 *  Gated on ``Boolean(addr)`` AND on the caller opting in
 *  via ``enabled: true`` -- the revision list is only fetched
 *  on demand (when the operator expands the History
 *  affordance), not on every detail-sheet open. */
export function useHostNoteRevisions(
  addr: string | undefined,
  options?: HookOptions<NoteRevision[]>,
): UseQueryResult<NoteRevision[]> {
  return useQuery<NoteRevision[]>({
    queryKey: ["notes", "host", addr, "revisions"],
    queryFn: ({ signal }) => fetchHostNoteRevisions(addr as string, signal),
    ...options,
    enabled: gatedEnabled(Boolean(addr), options),
  });
}

/** Mutation hook that wraps :func:`saveHostNote` and
 *  invalidates the affected ``useHostNote`` / revision queries
 *  on success so the panel refreshes without a manual
 *  refetch. */
export function useSaveHostNote(
  addr: string | undefined,
): UseMutationResult<
  SaveHostNoteResult,
  Error,
  { body: string; mode: SaveHostNoteMode }
> {
  const queryClient = useQueryClient();
  return useMutation<
    SaveHostNoteResult,
    Error,
    { body: string; mode: SaveHostNoteMode }
  >({
    mutationFn: ({ body, mode }) => saveHostNote(addr as string, body, mode),
    onSuccess: (result) => {
      // ``conflict`` / ``unauthorized`` / ``too_large`` /
      // ``not_found`` are not real success states from the
      // operator's perspective, but ``useMutation``'s onSuccess
      // fires whenever the mutationFn returns without
      // throwing.  Only invalidate on a real ``saved``.
      if (result.kind === "saved") {
        // Invalidate every affected key explicitly rather
        // than relying on ``invalidateQueries``'s default
        // prefix match (which would still catch the
        // revisions / listing keys today, but creates a
        // hidden dependency on that behaviour -- a future
        // migration to ``exact: true`` or a queryKey reshape
        // would silently leave stale entries in the cache
        // after a save).
        queryClient.invalidateQueries({
          queryKey: ["notes", "host", addr],
        });
        queryClient.invalidateQueries({
          queryKey: ["notes", "host", addr, "revisions"],
        });
        // Notes Explorer listing: a host-note save changes
        // ``revision`` / ``updated_at`` / ``updated_by`` for
        // the affected row (and creates a new row for
        // ``create`` mode).  Without this invalidation, the
        // listing keeps serving the pre-save snapshot for
        // the app-wide ``staleTime`` window (see
        // ``QueryClient`` in ``routes/root.tsx``) so an
        // operator who edits a note then navigates to the
        // Notes tab would see stale data.  Prefix
        // invalidation (``["notes", "list"]``) catches every
        // variant of the listing key emitted by
        // :func:`useNotes` (filter dimensions are tail
        // elements of the key).
        queryClient.invalidateQueries({
          queryKey: ["notes", "list"],
        });
      }
    },
  });
}

/** Mutation hook that wraps :func:`deleteHostNote` and
 *  invalidates the affected queries on success. */
export function useDeleteHostNote(
  addr: string | undefined,
): UseMutationResult<boolean, Error, void> {
  const queryClient = useQueryClient();
  return useMutation<boolean, Error, void>({
    mutationFn: () => deleteHostNote(addr as string),
    onSuccess: () => {
      // Invalidate regardless of the ``existed`` return value:
      // when the server returns 404 (already deleted by
      // someone else), the local cache may still hold the
      // previously-found note from before the race, and
      // skipping the refetch would leave the panel showing
      // the stale entry until something else triggers a
      // reload.  Invalidating in both cases keeps the cache
      // honest.  See ``useSaveHostNote`` above for the
      // rationale on listing every query key explicitly
      // rather than relying on prefix-match defaults.
      queryClient.invalidateQueries({
        queryKey: ["notes", "host", addr],
      });
      queryClient.invalidateQueries({
        queryKey: ["notes", "host", addr, "revisions"],
      });
      // Notes Explorer listing: a host-note deletion drops
      // the affected row from the listing.  Without this
      // invalidation the Explorer tab keeps showing the
      // deleted row for the app-wide ``staleTime`` window.
      // See ``useSaveHostNote`` for the same rationale.
      queryClient.invalidateQueries({
        queryKey: ["notes", "list"],
      });
    },
  });
}

/** Query parameters accepted by the listing endpoint
 *  ``GET /cgi/notes/``.  All fields are optional.  ``q`` runs a
 *  ``$text`` query over note bodies; ``entity_type`` narrows to
 *  one type; ``limit`` / ``skip`` paginate. */
export interface NotesListParams {
  entityType?: string;
  q?: string;
  limit?: number;
  skip?: number;
}

/** Fetch the notes listing as a JSON array.  Each entry has the
 *  full :ts:type:`Note` shape (``entity_key`` in caller-facing
 *  form -- printable IP string for ``host``, etc.).  The
 *  endpoint does not surface a 501 distinction in the list
 *  shape; backends without notes support 501 the route and
 *  surface as :ts:type:`Error` from this function (the SPA
 *  hides the Notes tab on those deployments via
 *  ``window.config.modules`` so users should not reach this
 *  call in practice). */
export async function fetchNotes(
  params: NotesListParams = {},
  signal?: AbortSignal,
): Promise<Note[]> {
  const url =
    CGI_ROOT +
    "/notes/" +
    qs({
      entity_type: params.entityType,
      q: params.q,
      limit: params.limit,
      skip: params.skip,
    });
  const response = await fetch(url, { credentials: "same-origin", signal });
  await ensureOk(response, `GET ${url}`);
  return (await response.json()) as Note[];
}

/** React Query hook around :func:`fetchNotes`.  Cache key
 *  includes every filter dimension so the panel re-fetches on
 *  any change.
 *
 *  Freshness: overrides the app-wide
 *  ``staleTime: 30_000`` (set on the root ``QueryClient`` in
 *  ``routes/root.tsx``) to ``0`` and forces
 *  ``refetchOnMount: "always"``.  Operators expect the Notes
 *  tab to reflect the current DB state -- not a 30-second-old
 *  snapshot -- whenever they navigate to it (covers
 *  cross-tab edits and any future mutation path that affects
 *  notes but skips the explicit invalidation in
 *  :func:`useSaveHostNote` / :func:`useDeleteHostNote`).
 *  Callers can pass ``options`` to override either default
 *  when a caching variant is needed. */
export function useNotes(
  params: NotesListParams,
  options?: HookOptions<Note[]>,
): UseQueryResult<Note[]> {
  return useQuery<Note[]>({
    queryKey: [
      "notes",
      "list",
      params.entityType ?? null,
      params.q ?? null,
      params.limit ?? null,
      params.skip ?? null,
    ],
    queryFn: ({ signal }) => fetchNotes(params, signal),
    staleTime: 0,
    refetchOnMount: "always",
    ...options,
    enabled: gatedEnabled(true, options),
  });
}
