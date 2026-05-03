/**
 * Passive-record helpers — recontype-aware value rendering.
 *
 * Time-series math (date coercion, density, stroke widths,
 * compact range formatting) is shared with the other sections
 * via :mod:`lib/timeline`; import ``timelineDateMs`` /
 * ``timelineDensity`` / ``timelineStrokeWidths`` /
 * ``formatTimelineRange`` from there.
 */
import type { PassiveRecord } from "@/lib/api";

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
