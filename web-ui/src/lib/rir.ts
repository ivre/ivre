/**
 * RIR-specific display helpers. Currently a single
 * range→CIDR collapser used by ``RirRecordCard`` to render
 * inet[6]num headlines as ``192.0.2.0/24`` rather than
 * ``192.0.2.0 — 192.0.2.255`` when the range happens to
 * align with a single CIDR prefix.
 */

/** Render an inet[6]num record's range as a CIDR when the
 *  ``(start, stop)`` pair collapses to one prefix; otherwise
 *  return ``null`` so the caller can fall back to displaying
 *  the raw endpoints.
 *
 *  A range collapses to a single CIDR iff:
 *    - ``(stop - start + 1)`` is a power of 2, and
 *    - ``start`` is aligned on that power of 2.
 *
 *  The address family is inferred from the ``start`` string: a
 *  dotted-quad means IPv4 (mask in [0, 32]), anything containing
 *  ``:`` means IPv6 (mask in [0, 128]). Mixed-family inputs
 *  return ``null``. */
export function rangeToCidr(start: string, stop: string): string | null {
  const startV6 = start.includes(":");
  const stopV6 = stop.includes(":");
  if (startV6 !== stopV6) return null;
  const totalBits = startV6 ? 128 : 32;
  let startInt: bigint;
  let stopInt: bigint;
  try {
    startInt = startV6 ? ipv6ToBigInt(start) : ipv4ToBigInt(start);
    stopInt = startV6 ? ipv6ToBigInt(stop) : ipv4ToBigInt(stop);
  } catch {
    return null;
  }
  if (stopInt < startInt) return null;
  const size = stopInt - startInt + 1n;
  // Power-of-2 check: a positive integer ``n`` is a power of 2
  // iff ``n & (n - 1) === 0``. Bit-length gives ``log2(size) + 1``
  // for any positive ``n``; we want ``log2`` exactly, so subtract 1.
  if ((size & (size - 1n)) !== 0n) return null;
  const hostBits = size === 1n ? 0 : bigIntBitLength(size) - 1;
  // Alignment: ``start`` must be a multiple of ``size``.
  if ((startInt & (size - 1n)) !== 0n) return null;
  const prefix = totalBits - hostBits;
  return `${start}/${prefix}`;
}

function ipv4ToBigInt(s: string): bigint {
  const parts = s.split(".");
  if (parts.length !== 4) throw new Error(`not IPv4: ${s}`);
  let n = 0n;
  for (const p of parts) {
    const o = Number(p);
    if (!Number.isInteger(o) || o < 0 || o > 255) {
      throw new Error(`octet out of range: ${p}`);
    }
    n = (n << 8n) | BigInt(o);
  }
  return n;
}

function ipv6ToBigInt(s: string): bigint {
  // Resolve ``::`` shorthand and any embedded IPv4 dotted-quad in
  // the last group (RFC 4291 §2.5.5: ``::ffff:1.2.3.4``).
  const lastColon = s.lastIndexOf(":");
  const tail = s.slice(lastColon + 1);
  let normalised = s;
  if (tail.includes(".")) {
    const v4 = ipv4ToBigInt(tail);
    const high = (v4 >> 16n) & 0xffffn;
    const low = v4 & 0xffffn;
    normalised =
      s.slice(0, lastColon + 1) +
      high.toString(16) +
      ":" +
      low.toString(16);
  }
  const doubleColon = normalised.indexOf("::");
  let groups: string[];
  if (doubleColon === -1) {
    groups = normalised.split(":");
  } else {
    const left = normalised.slice(0, doubleColon);
    const right = normalised.slice(doubleColon + 2);
    const lparts = left === "" ? [] : left.split(":");
    const rparts = right === "" ? [] : right.split(":");
    const fill = 8 - lparts.length - rparts.length;
    if (fill < 0) throw new Error(`too many groups: ${s}`);
    groups = [...lparts, ...Array(fill).fill("0"), ...rparts];
  }
  if (groups.length !== 8) throw new Error(`expected 8 groups: ${s}`);
  let n = 0n;
  for (const g of groups) {
    const v = parseInt(g || "0", 16);
    if (!Number.isInteger(v) || v < 0 || v > 0xffff) {
      throw new Error(`group out of range: ${g}`);
    }
    n = (n << 16n) | BigInt(v);
  }
  return n;
}

function bigIntBitLength(n: bigint): number {
  // Approximate via string length in hex; cheap enough for the
  // 128-bit values we care about.
  if (n === 0n) return 0;
  return n.toString(2).length;
}
