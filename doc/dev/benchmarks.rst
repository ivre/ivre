Benchmarks
##########

``ivre bench`` measures the performance of the configured backend by
running a fixed set of workloads (*scenarios*) and emitting a JSON
report of per-scenario latency metrics. It exists so that a backend
change or a shared-helper refactor can be checked for performance
regressions, and so the supported backends can be compared on the same
data.

Functional parity (a query returns the right rows on every backend)
does not imply performance parity: a missing index or a poor query plan
can make an otherwise-correct backend orders of magnitude slower.
``ivre bench`` turns that invisible difference into a number.

Running
=======

The backend is the one selected by ``ivre.conf`` (``DB = ...``); run the
tool once per backend you want to compare. ``--backend`` only labels the
report (it is auto-detected from the configured URL when omitted)::

    $ ivre bench --list                     # show available scenarios
    $ ivre bench                             # run every scenario
    $ ivre bench --scenario bench_top_service
    $ ivre bench --backend postgresql --output pg.json

The scenarios read the ``view`` purpose, so the figures are only
meaningful against a **populated** database; the numbers from an empty
store are not comparable.

Options:

``--list``
    List the available scenarios and exit.
``--scenario NAME``
    Run a single scenario (repeatable; default: all). See ``--list``.
``--backend NAME``
    Backend label recorded in the report (default: detected from the
    configured DB).
``--iterations N``
    Timed iterations per scenario (default: 20).
``--warmup N``
    Untimed warmup iterations per scenario, run before timing to prime
    caches / connection pools (default: 3).
``--output FILE``
    Write the JSON report to ``FILE`` (default: stdout).

Output
======

One JSON document per run, carrying the IVRE version, the backend
label, the Python/platform identification, and one record per scenario.
Each record reports latency in milliseconds as ``min`` / ``p50`` /
``p95`` / ``max`` / ``mean`` (percentiles are nearest-rank, so every
reported value was actually measured)::

    {
      "backend": "postgresql",
      "ivre_version": "...",
      "python": "3.12.x",
      "platform": "...",
      "results": [
        {
          "scenario": "bench_top_service",
          "description": "Top 15 service values across the whole view.",
          "iterations": 20,
          "warmup": 3,
          "latency_ms": {"min": ..., "p50": ..., "p95": ..., "max": ..., "mean": ...}
        }
      ]
    }

Archiving these records (e.g. as CI artefacts) gives a latency trend per
backend over time.

Scenarios
=========

The set is intentionally small at first and grows as new workloads are
added; ``ivre bench --list`` is always the authoritative list. Each
scenario is a single, cursor-materialising unit of work so the whole
query cost is measured:

``bench_top_service``
    Top 15 ``service`` values over the whole view (``ivre view --top
    service --limit 15``).
``bench_top_port``
    Top 15 ports over the whole view (``ivre view --top port --limit
    15``).

Adding a scenario is one entry in ``SCENARIOS`` in
:mod:`ivre.tools.bench`.
