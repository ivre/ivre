/**
 * Passive-record helpers — date coercion, recontype-aware value
 * rendering, and the line-thickness math driving the timeline
 * widget.
 */
import type { PassiveRecord } from "@/lib/api";

/** Convert a passive record's ``firstseen`` / ``lastseen`` to
 *  milliseconds since the Unix epoch, regardless of whether the
 *  backend returned a number (default: seconds) or an ISO-ish
 *  string (when ``datesasstrings=1`` was requested). Returns
 *  ``NaN`` on parse failure so callers can filter out broken
 *  records without throwing. */
export function passiveDateMs(value: number | string | undefined): number {
  if (value === undefined || value === null) return Number.NaN;
  if (typeof value === "number") {
    // Heuristic: timestamps before 10^11 are seconds (anything up
    // to year 5138); larger values are already milliseconds.
    return value < 1e11 ? value * 1000 : value;
  }
  // ISO-ish string. The backend emits ``"2015-09-18 16:13:35.515000"``
  // (space, no timezone). Replace the space with ``T`` so
  // ``Date.parse`` treats it as ISO-8601; the absence of a timezone
  // means the browser interprets it as local time, which matches
  // the AngularJS UI's behaviour.
  const iso = value.replace(" ", "T");
  return Date.parse(iso);
}

/** A record's duration in seconds (``lastseen - firstseen``).
 *  Clamped to ``>= 0``; a record where both timestamps are
 *  identical reports ``0`` seconds. */
export function passiveDurationSeconds(record: PassiveRecord): number {
  const first = passiveDateMs(record.firstseen);
  const last = passiveDateMs(record.lastseen);
  if (Number.isNaN(first) || Number.isNaN(last)) return 0;
  return Math.max(0, (last - first) / 1000);
}

/** Density = ``count / max(duration_seconds, 1)``. Higher density
 *  → the record concentrates more observations per unit time and
 *  is rendered as a thicker line on the timeline. The ``max(_, 1)``
 *  prevents division-by-zero on instant records (``firstseen ===
 *  lastseen``) and stops single-second records from dominating
 *  the scale. */
export function passiveDensity(record: PassiveRecord): number {
  return record.count / Math.max(passiveDurationSeconds(record), 1);
}

/** Map a list of records to ``[strokeWidth_px, ...]`` according
 *  to the design spec: width grows with ``count / duration``,
 *  normalised against the max density of the visible set, then
 *  mapped onto the closed interval ``[minWidth, maxWidth]``.
 *
 *  Deterministic on the empty input (returns ``[]``) and on a
 *  list whose densities are all equal (returns ``maxWidth`` for
 *  every record). */
export function passiveStrokeWidths(
  records: readonly PassiveRecord[],
  options: { minWidth?: number; maxWidth?: number } = {},
): number[] {
  const minWidth = options.minWidth ?? 1;
  const maxWidth = options.maxWidth ?? 8;
  if (records.length === 0) return [];
  const densities = records.map(passiveDensity);
  const max = Math.max(...densities);
  if (max <= 0) {
    return records.map(() => minWidth);
  }
  return densities.map((d) => {
    const normalised = d / max;
    return minWidth + normalised * (maxWidth - minWidth);
  });
}

/** Format a passive record's date range as a compact human
 *  string (``"2024-01-02 10:00 → 2024-03-15 09:30"``). Used in
 *  the card header. */
export function formatPassiveRange(record: PassiveRecord): string {
  const fmt = (ms: number): string => {
    if (!Number.isFinite(ms)) return "?";
    const d = new Date(ms);
    const pad = (n: number) => String(n).padStart(2, "0");
    return (
      `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}` +
      ` ${pad(d.getHours())}:${pad(d.getMinutes())}`
    );
  };
  return `${fmt(passiveDateMs(record.firstseen))} → ${fmt(passiveDateMs(record.lastseen))}`;
}

/* ------------------------------------------------------------------ */
/* Recontype-aware value rendering                                    */
/* ------------------------------------------------------------------ */

export interface PassiveValueDisplay {
  /** Short label rendered above the body (e.g. ``"DNS A"``,
   *  ``"HTTP Server"``, ``"TLS cert (subject)"``). */
  heading?: string;
  /** Primary content; a string for simple cases, an object for
   *  the structured ones (e.g. cert subject + issuer + sha1). */
  primary: string;
  /** Optional secondary line (e.g. cert SHA1, JA3 raw). */
  secondary?: string;
}

const _str = (v: unknown): string =>
  typeof v === "string" || typeof v === "number" ? String(v) : "";

/** Build a presentation-friendly description of a passive record.
 *  Recontype-aware: DNS answers, HTTP server headers, TLS certs,
 *  JA3 fingerprints, SSH host keys, and TCP banners each get a
 *  shape that highlights the most useful field for an operator.
 *  Falls back to a generic ``recontype`` heading + raw ``value``
 *  for everything else. */
export function describePassiveValue(
  record: PassiveRecord,
): PassiveValueDisplay {
  const recontype = record.recontype;

  if (recontype === "DNS_ANSWER") {
    const rrtype = record.rrtype ?? "";
    if (record.targetval) {
      // CNAME / MX / NS / PTR style — value is the queried name,
      // targetval is the canonical name.
      return {
        heading: `DNS ${rrtype || "answer"}`,
        primary: `${record.value} → ${record.targetval}`,
      };
    }
    if (record.addr) {
      // A / AAAA — value is the queried name, addr is the
      // resolved address.
      return {
        heading: `DNS ${rrtype || "answer"}`,
        primary: `${record.value} → ${record.addr}`,
      };
    }
    return {
      heading: `DNS ${rrtype || "answer"}`,
      primary: record.value,
    };
  }

  if (
    recontype === "HTTP_SERVER_HEADER" ||
    recontype === "HTTP_CLIENT_HEADER" ||
    recontype === "HTTP_CLIENT_HEADER_SERVER"
  ) {
    const header = record.source ?? "header";
    return {
      heading:
        recontype === "HTTP_SERVER_HEADER"
          ? `HTTP server header (${header})`
          : recontype === "HTTP_CLIENT_HEADER_SERVER"
            ? `HTTP client (${header})`
            : `HTTP client header (${header})`,
      primary: record.value,
    };
  }

  if (recontype === "SSL_SERVER" || recontype === "SSL_CLIENT") {
    const source = record.source ?? "";
    if (source === "cert" || source === "cacert") {
      const subject = _str(record.infos?.["subject_text"]);
      const issuer = _str(record.infos?.["issuer_text"]);
      const sha1 = _str(record.infos?.["sha1"]);
      return {
        heading: `TLS ${recontype === "SSL_SERVER" ? "server" : "client"} ${source}`,
        primary: subject || "(no subject)",
        secondary: [
          issuer ? `Issuer: ${issuer}` : "",
          sha1 ? `SHA1: ${sha1}` : "",
        ]
          .filter(Boolean)
          .join("  ·  "),
      };
    }
    if (source.startsWith("ja3")) {
      const sha1 = _str(record.infos?.["sha1"]);
      return {
        heading: `JA3${recontype === "SSL_SERVER" ? "-S" : ""}`,
        primary: record.value,
        secondary: sha1 ? `SHA1: ${sha1}` : undefined,
      };
    }
    if (source.startsWith("ja4")) {
      return {
        heading: `JA4${recontype === "SSL_SERVER" ? "-S" : ""}`,
        primary: record.value,
      };
    }
    return {
      heading: `TLS ${recontype === "SSL_SERVER" ? "server" : "client"} (${source || "?"})`,
      primary: record.value,
    };
  }

  if (recontype === "SSH_SERVER_HOSTKEY") {
    const algo = record.source ?? "";
    return {
      heading: `SSH host key${algo ? ` (${algo})` : ""}`,
      primary: record.value,
    };
  }

  if (recontype === "SSH_CLIENT" || recontype === "SSH_SERVER") {
    return {
      heading: recontype === "SSH_CLIENT" ? "SSH client" : "SSH server",
      primary: record.value,
    };
  }

  if (recontype === "SSH_CLIENT_HASSH" || recontype === "SSH_SERVER_HASSH") {
    return {
      heading:
        recontype === "SSH_CLIENT_HASSH" ? "HASSH (client)" : "HASSH (server)",
      primary: record.value,
    };
  }

  if (recontype === "TCP_SERVER_BANNER" || recontype === "TCP_CLIENT_BANNER") {
    return {
      heading:
        recontype === "TCP_SERVER_BANNER"
          ? "TCP banner (server)"
          : "TCP banner (client)",
      primary: record.value,
    };
  }

  if (recontype === "MAC_ADDRESS") {
    return {
      heading: "MAC address",
      primary: record.value,
      secondary: record.source ? `via ${record.source}` : undefined,
    };
  }

  if (recontype === "OPEN_PORT") {
    return {
      heading: "Open port",
      primary: record.value || `${record.port ?? "?"}`,
    };
  }

  // Generic fallback.
  return {
    heading: recontype.toLowerCase().replace(/_/g, " "),
    primary: record.value,
  };
}
