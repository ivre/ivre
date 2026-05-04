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
