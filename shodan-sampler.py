import json, sys

want = [
    "tags",
    "vulns",
    "html",
    "server",
    "title",
    "robots",
    "sitemap",
    "securitytxt",
    "components",
    "redirects",
    "dom_hash",
    "headers_hash",
    "html_hash",
    "robots_hash",
    "sitemap_hash",
    "securitytxt_hash",
    "server_hash",
    "title_hash",
    "ip_str",
    "host",
    "port",
    "transport",
    "status",
    "product",
    "version",
]


def score(r):
    return sum(1 for k in want if k in r and r[k] is not None)


best = []  # (score, line_no, rec)
bad = 0
with open("fixed_results.json", "r", encoding="utf-8", errors="replace") as f:
    for i, line in enumerate(f, start=1):
        if not line.strip():
            continue
        try:
            r = json.loads(line)
        except Exception:
            bad += 1
            continue
        s = score(r)
        best.append((s, i, r))
        if i >= 50000:  # safety cap; remove/raise if you want
            break

best.sort(key=lambda x: (x[0], x[1]), reverse=True)
print("parsed_records:", len(best), "bad_lines_skipped:", bad)
for s, i, r in best[:3]:
    out = {k: r.get(k) for k in want if k in r}
    # shrink huge string bodies but keep type information
    for k in ["html", "robots", "sitemap", "securitytxt"]:
        if k in out and isinstance(out[k], str):
            out[k] = {"len": len(out[k]), "prefix": out[k][:200]}
    print(f"\n=== auto-picked line {i} score {s} ===")
    print(json.dumps(out, indent=2, ensure_ascii=False))
