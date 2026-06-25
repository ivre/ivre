#! /usr/bin/env python

# This file is part of IVRE.
# Copyright 2011 - 2026 Pierre LALET <pierre@droids-corp.org>
#
# IVRE is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# IVRE is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
# License for more details.
#
# You should have received a copy of the GNU General Public License
# along with IVRE. If not, see <http://www.gnu.org/licenses/>.


"""Benchmark IVRE backends.

Runs a fixed set of workloads (scenarios) against the configured
backend and emits a JSON report of per-scenario latency metrics, so a
backend change or a refactor can be checked for performance regressions
and different backends can be compared on the same fixtures.

The backend is the one selected by ``ivre.conf`` (``DB = ...``); run the
tool once per backend (``--backend`` only labels the report). Scenarios
read the ``view`` purpose and need a populated database to be
meaningful -- the figures from an empty database are not comparable.
"""

import argparse
import collections
import json
import math
import platform
import statistics
import sys
import time
from collections.abc import Callable, Iterable
from typing import Any
from urllib.parse import urlparse

from ivre import VERSION
from ivre.db import db


def _drain(iterable: Iterable[Any]) -> None:
    """Consume an iterable fully without retaining it, so a scenario
    measures the backend's query cost (the cursor is forced to run)
    rather than the cost of building a Python list of a potentially
    large result set."""
    collections.deque(iterable, maxlen=0)


def _top(field: str) -> Callable[[], None]:
    """Build a scenario fetching the top 15 values of ``field`` over the
    whole view -- ``ivre view --top <field> --limit 15``.

    Note the call order: ``DBActive.topvalues`` (which ``db.view`` uses)
    takes ``field`` first and ``flt`` as an optional keyword (unlike
    ``DBFlow.topvalues``, whose aggregation contract is ``flt`` first).
    """

    def _run() -> None:
        _drain(db.view.topvalues(field, flt=db.view.flt_empty, topnbr=15))

    return _run


# Scenario registry: name -> (one-line description, timed callable).
SCENARIOS: dict[str, tuple[str, Callable[[], None]]] = {
    "bench_top_service": (
        "Top 15 service values across the whole view.",
        _top("service"),
    ),
    "bench_top_port": (
        "Top 15 ports across the whole view.",
        _top("port"),
    ),
}


def _percentile(sorted_values: list[float], quantile: float) -> float:
    """Nearest-rank percentile of an already-sorted, non-empty list.

    ``quantile`` is in ``[0, 1]``. The rank is ``ceil(quantile * N)``
    clamped to ``[1, N]``; nearest-rank is chosen over interpolation
    because it is unambiguous for the small sample sizes a benchmark
    run produces and never invents a value that was not measured.
    """
    if not sorted_values:
        raise ValueError("cannot take a percentile of an empty sample")
    if not 0.0 <= quantile <= 1.0:
        raise ValueError("quantile must be in [0, 1]")
    rank = max(1, math.ceil(quantile * len(sorted_values)))
    return sorted_values[min(rank, len(sorted_values)) - 1]


def _time_callable(
    func: Callable[[], None], *, iterations: int, warmup: int
) -> dict[str, Any]:
    """Time ``func`` over ``iterations`` runs (after ``warmup`` untimed
    runs) and return the latency summary (all values in milliseconds).
    """
    for _ in range(warmup):
        func()
    samples_ms: list[float] = []
    for _ in range(iterations):
        start = time.perf_counter()
        func()
        samples_ms.append((time.perf_counter() - start) * 1000.0)
    samples_ms.sort()
    return {
        "iterations": iterations,
        "warmup": warmup,
        "latency_ms": {
            "min": round(samples_ms[0], 3),
            "p50": round(_percentile(samples_ms, 0.50), 3),
            "p95": round(_percentile(samples_ms, 0.95), 3),
            "max": round(samples_ms[-1], 3),
            "mean": round(statistics.fmean(samples_ms), 3),
        },
    }


def run_scenario(name: str, *, iterations: int, warmup: int) -> dict[str, Any]:
    """Run one registered scenario and return its JSON-ready record."""
    description, func = SCENARIOS[name]
    record = _time_callable(func, iterations=iterations, warmup=warmup)
    record["scenario"] = name
    record["description"] = description
    return record


def _detect_backend() -> str:
    """Best-effort backend label derived from the configured DB URL
    (same scheme normalisation as :meth:`ivre.db.MetaDB.get_class`)."""
    url = db.urls.get("view") or db.url
    if not url:
        return "unknown"
    scheme = urlparse(url).scheme
    return {
        "https": "http",
        "mongodb+srv": "mongodb",
        "elastics": "elastic",
    }.get(scheme, scheme) or "unknown"


def main() -> None:
    """Benchmark IVRE backends."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--list",
        action="store_true",
        help="List the available scenarios and exit.",
    )
    parser.add_argument(
        "--scenario",
        action="append",
        metavar="NAME",
        help="Scenario to run (repeatable; default: all). See --list.",
    )
    parser.add_argument(
        "--backend",
        metavar="NAME",
        help="Backend label recorded in the report "
        "(default: detected from the configured DB).",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=20,
        metavar="N",
        help="Timed iterations per scenario (default: 20).",
    )
    parser.add_argument(
        "--warmup",
        type=int,
        default=3,
        metavar="N",
        help="Untimed warmup iterations per scenario (default: 3).",
    )
    parser.add_argument(
        "--output",
        metavar="FILE",
        help="Write the JSON report to FILE (default: stdout).",
    )
    args = parser.parse_args()

    if args.list:
        for name in sorted(SCENARIOS):
            sys.stdout.write(f"{name}\t{SCENARIOS[name][0]}\n")
        return

    if args.iterations < 1:
        parser.error("--iterations must be a positive integer")
    if args.warmup < 0:
        parser.error("--warmup must be a non-negative integer")

    scenarios = args.scenario if args.scenario else sorted(SCENARIOS)
    unknown = [name for name in scenarios if name not in SCENARIOS]
    if unknown:
        parser.error(
            f"unknown scenario(s): {', '.join(unknown)} (see `ivre bench --list`)"
        )

    report: dict[str, Any] = {
        "ivre_version": VERSION,
        "backend": args.backend or _detect_backend(),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "results": [
            run_scenario(name, iterations=args.iterations, warmup=args.warmup)
            for name in scenarios
        ],
    }
    rendered = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        with open(args.output, "w", encoding="utf8") as fdesc:
            fdesc.write(rendered + "\n")
    else:
        sys.stdout.write(rendered + "\n")
