# Progress

Current state, what is next, and what is easy to get wrong. The *why* behind
design choices lives in `adr/`; the architecture in `PLANNING.md`.

## State

v0.1.0 is released on PyPI as `inject-probe`: 15 probes across 3 attack
classes, callable and HTTP/chat adapters, JSON reports, baseline gating.

## Next

1. Releases: bump `__version__` in `src/inject_probe/__init__.py`, then create
   a GitHub release with a matching `vX.Y.Z` tag. The upload to PyPI waits for
   approval in the `pypi` environment.
2. Optionally rename the GitHub repository to `inject-probe` to match the
   distribution name. GitHub redirects the old URL, so the README install line
   keeps working.
3. Corpus v2, held out — see the isolation rules in `PLANNING.md`.

## Things to know

- **Resolve every citation before writing it.** An arXiv ID recalled from memory
  once pointed at an unrelated paper. Every ID in the corpus has been fetched and
  title-checked; keep it that way.
- **Write non-ASCII in the corpus as `\uXXXX` escapes.** A homoglyph you cannot
  see is a payload nobody can review, and ruff's `RUF001` flags the literals.
  Tests import `_HOMOGLYPHS` from the corpus rather than repeating the characters.
- **`tests/` must stay free of `__init__.py`.** `tests/dotted_target.py` and the
  helpers in `tests/targets.py` are imported by name, which relies on pytest's
  default `prepend` import mode. That is also why helpers are not in a
  `conftest.py`.
- **pytest's `sys.path` hides target-loading bugs.** It once masked that dotted
  specs failed from the installed console script. Check target-loading changes
  through `uv run inject-probe`, not only through the suite.
- **Guards that look paranoid and are not:**
  `test_report_contains_no_wall_clock_fields` stops a helpful `generated_at` from
  breaking byte-identical reports and every committed baseline;
  `success_rate` is rounded so float noise cannot do the same; the echo test
  sweeps 25 seeds because one seed proves nothing; determinism is tested across
  `--concurrency` values because an `as_completed` regression would pass every
  serial test.
- **`examples/vulnerable.py` scores 0/7 on encoding because it never decodes**,
  not because it defends. Keep that profile: it is what shows the README's
  "read encoding alongside direct" point.
- **Probe ids are baseline keys.** Renaming a payload function breaks every
  recorded baseline.

## History

Newest first. Details are in the commits.

- **2026-11-19** — Pre-public review. Fixed `--json X --baseline X` comparing a
  run against itself, target loading from the installed CLI (dotted specs,
  sibling imports, directory specs), a callable that raised crashing the run, and
  tracebacks on bad input. Any errored probe now fails the baseline gate. README
  corrected and trimmed; docs cleaned up.
- **2026-07-28** — Phases 0–4: tooling and CI, the three attack classes, adapters,
  report and CLI, baseline gating, ADRs, README.
