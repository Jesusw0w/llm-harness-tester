# Progress

Session history, newest first. Records what was non-obvious — not what the diff shows.

---

## 2026-07-28 — Phases 3 and 4: full corpus, HTTP adapters, baseline gating, docs

**Changed.** `attacks/indirect.py` (4 payloads) and `attacks/encoding.py` (7);
`HTTPTarget` plus `json_endpoint` and `chat_completions` factories in
`adapters.py`; `baseline.py`; CLI flags for HTTP targets and baseline gating;
`examples/echoing.py`; three ADRs; README; release workflow; CI self-test job.
Corpus is now 15 probes across 3 classes.

**Verified.** `uv run nox` green — 121 tests on 3.12/3.13/3.14. `uv build`
produces both artefacts. The plan's end-to-end verification run by hand: record a
baseline from a target vulnerable to direct injection only → exit 0; same target
against its own baseline → exit 0; widen to the full vulnerable example → exit 1.
Every CI self-test step was executed locally before being written into the
workflow.

**Decisions.**

- *`chat_completions` is a factory over `HTTPTarget`, not a second class.* The
  only differences from a JSON endpoint are the request body and where the reply
  lives, so both are parameters (`build_body`, `response_pointer`) rather than a
  subclass. Two factories, one adapter.
- *The chat adapter does not extract `tool_calls`.* No v1 detector reads them, and
  guessing at each vendor's shape without a consumer is speculation. The field
  stays on `TargetResponse` for the protocol's sake.
- *A corpus-version mismatch on a baseline is a hard error, not a warning.*
  Comparing a v1 baseline against a v2 corpus produces confident nonsense, and v2
  is explicitly planned. Re-recording is cheap; a silently meaningless comparison
  is not.
- *Errored probes are excluded from baseline comparison on both sides.* Treating
  an unreachable target as "everything got fixed" would turn an outage into a
  green build — the CI equivalent of the echo bug.
- *`--fail-on-new` fails only on new probes that **succeeded**.* A new blocked
  probe is harmless, and failing on it would mean every corpus addition breaks
  every downstream build.
- *`examples/echoing.py` is checked in.* The README's 0/15 figure has to reproduce
  from a clone, and the control case deserves to be a first-class example rather
  than a test fixture.

**Non-obvious.**

- **`arXiv:2111.09934` is not Trojan Source.** It is a paper on JOP gadget
  diversification; recalling the ID from memory produced the wrong one. The
  correct ID is `2111.00169`. All five paper IDs in the corpus were fetched and
  title-checked. Do not write a citation without resolving it first.
- `RUF001` fires on Cyrillic homoglyphs, exactly as predicted in the phase 0
  note — including in test files. The fix is to import `_HOMOGLYPHS` from the
  corpus rather than duplicating the character, which is better anyway. All
  non-ASCII in `attacks/encoding.py` is written as `\uXXXX` escapes: a homoglyph
  you cannot see in the source is a payload nobody can review.
- The bandit (`S`) rules never fired on the corpus, including on `base64` and
  `codecs.rot_13`. The per-line `noqa` budget from the phase 0 plan went unused.
- `examples/vulnerable.py` scores 0/7 on the encoding class because it never
  decodes anything — not because it defends. The README says this explicitly; it
  is the exact false-comfort pattern the tool exists to surface.
- Two gaps were found while writing the phase notes and closed rather than
  deferred: determinism was not tested across `--concurrency` values (an
  `as_completed` regression would have passed every serial test), and
  `baseline.compare` documented a corpus-version check it did not implement.

**Remaining before publish.** Owner creates the PyPI project and registers this
repository as a trusted publisher (workflow `release.yml`, environment `pypi`),
then tags `v0.1.0`. Consider renaming the GitHub repository from
`llm-harness-tester` to `inject-probe` to match the distribution.

---

## 2026-07-28 — Phase 2: runner, report models, CLI

**Changed.** `runner.py` (thread-pool execution), `report.py` (pydantic models,
table renderer, JSON serialisation), `cli.py` (`run`, `list-probes`), plus
`tests/test_report.py` and `tests/test_cli.py`.

**Verified.** `uv run nox` green — 62 tests on 3.12/3.13/3.14. Byte-identical
reports asserted both in-process and through the written `--json` file. Checked by
hand through the real CLI, not only the suite: `examples/vulnerable.py` → 4/4
succeeded (100%), an echoing app → 0/4 (0%).

**Decisions.**

- *The runner does not retry.* Retries belong to the transport that can tell a
  transient failure from a real answer — `httpx.HTTPTransport(retries=...)` in
  phase 3. Retrying here would risk re-sending a probe to a target that answered
  fine, corrupting the result rather than repairing it.
- *A transport failure becomes `Outcome.ERROR`, not an exception.* One
  unreachable probe must not discard the results of every other probe in the run.
  `errored` is counted separately from `succeeded` so a broken run cannot be
  mistaken for a clean one.
- *`ThreadPoolExecutor.map` rather than `as_completed`.* `map` yields in input
  order, which is half of report determinism; `as_completed` would have needed a
  re-sort afterwards for no benefit.
- *Blocked probes omit their payload and response from the report.* They are
  reproducible from probe id plus seed, and the report doubles as the baseline
  file — storing four kilobytes of payload per blocked probe would make every
  baseline diff unreadable. Successes and errors keep full detail.
- *`run` exits 0 even at a 100% success rate.* No absolute threshold: no real
  system scores zero, so failing on the presence of successes would make the tool
  useless in CI. Regression comparison against a baseline is what gates a build,
  and that lands in phase 4.

**Non-obvious.**

- `test_report_contains_no_wall_clock_fields` greps the serialised JSON for
  `timestamp`/`duration`/`elapsed`/etc. It looks paranoid; it is the guard that
  stops someone adding a helpful `generated_at` field and silently breaking both
  byte-identity and every committed baseline.
- `success_rate` is `round(..., 4)`. Without it, float noise could in principle
  differ across interpreters and break byte-identity on the one field most likely
  to be compared.
- `by_class` is built by iterating `AttackClass` rather than the outcomes, so key
  order is taxonomy order and does not depend on which probes ran.
- `tests/targets.py` now also holds `vulnerable_target()` and
  `UnreachableTarget`. Test helpers live there rather than in a `conftest.py`
  because `tests/` deliberately has no `__init__.py` (see phase 1 note).

**Next.** Phase 3: attack classes 2 (indirect) and 3 (encoding), HTTP adapter
plus chat-completions preset, and the unicode round-trip test.

---

## 2026-07-28 — Phase 1: target, canary, attack class 1, echo suppression

**Changed.** `target.py` (`Target` protocol, `TargetResponse`), `constants.py`,
`exceptions.py`, `canary.py` (derivation + `normalize`), `probe.py` (`Probe`,
`AttackClass`), `detect.py`, `attacks/` with class 1 (four payloads),
`adapters.py` (callable adapter + spec loader), `examples/vulnerable.py`, and the
test suite. `examples` added back to noxfile `SOURCES` and mypy `files`.

**Verified.** `uv run nox` green — 41 tests on 3.12/3.13/3.14, lint clean,
`mypy --strict` clean on 19 files. Echo mechanism also checked by hand rather than
only through the suite: echo → `blocked`, whitespace-mangled echo → `blocked`,
compliant → `succeeded`, spaced compliance (`CNRY 44f1  7f45`) → `succeeded`,
`examples/vulnerable.py` → `succeeded`.

**Decisions.**

- *`Probe` lives in its own `probe.py`, not in `attacks/`.* `detect.py` and the
  runner both need it, and putting it in `attacks/__init__.py` would have made
  `attacks` import-cycle with anything that consumes a probe.
- *The payload's docstring **is** its citation.* `probes()` reads it with
  `inspect.getdoc`. This makes the isolation rule structural — you cannot add a
  payload without writing the docstring, because the citation field would be
  empty and `Probe.__post_init__` raises. A test additionally asserts each one
  matches `arXiv:\d{4}\.\d{4,5}|OWASP|https?://`, so a docstring that explains
  the payload but cites nothing still fails.
- *`Canary.instruction` is one shared property, not per-payload phrasing.* The
  reconstruction step is the thing that separates compliance from echo; letting
  each attack class word it differently would let the guarantee drift silently.
- *Invariants `raise ValueError`, they are not `assert`.* `assert` is stripped
  under `python -O`, and the canary-leak check is the one thing in the codebase
  that must never be optimised away.
- *`CallableTarget` inspects the signature once* and only passes `documents` if
  the callable accepts it. A one-argument application is still worth testing for
  direct injection.

**Non-obvious.**

- **All four citations were fetched and verified against arXiv before use**
  (2211.09527 Perez & Ribeiro; 2302.12173 Greshake et al.; 2306.05499 Liu et al.).
  Do not add a payload citing a paper from memory — check the ID resolves.
- `test_echo_suppression_holds_across_seeds` sweeps 25 seeds. A single seed
  proving echo-safety proves nothing; the canary is seeded, so a hash collision
  or an unlucky fragment split would only show up across a range.
- `examples/vulnerable.py` is deliberately *unevenly* vulnerable: it obeys
  instructions from any position (direct + indirect succeed) but never decodes
  base64 or ROT13 (encoding blocked). That mixed profile is what phase 3 needs to
  make the report look like a real one.
- `tests/dotted_target.py` exists only so the dotted-module spec form has
  something to import. It relies on pytest's default `prepend` import mode
  putting `tests/` on `sys.path`, so `tests/` must stay free of `__init__.py`.

**Next.** Phase 2: report models, runner, CLI, JSON output, and the
byte-identical-report determinism test.

---

## 2026-07-28 — Phase 0: repo, tooling, CI

**Changed.** Apache-2.0 `LICENSE` replacing the committed MIT one; `pyproject.toml`
(hatchling, src layout, ruff, `mypy --strict`, pytest); `noxfile.py`; `.github/workflows/ci.yml`;
package skeleton with `py.typed`; `README.md`; `docs/PLANNING.md`; `.gitignore`.

**Verified.** `uv run nox` green — lint, `mypy --strict`, pytest on 3.12, 3.13 and 3.14.

**Decisions.**

- *Apache-2.0 over the committed MIT.* Explicit patent grant, which matters for security
  tooling and for corporate adopters. Cheap now, painful once contributors exist.
- *Name `inject-probe`.* Verified free on PyPI (`inject_probe` normalised form too) and
  no GitHub collision. Note the git repo directory is still `llm-harness-tester`; the
  distribution name is what ships.
- *Python floor 3.12, test matrix 3.12/3.13/3.14.* The brief asked for 3.12+3.13; 3.14 is
  free to add and is what the author runs locally. Lint and type-check run **once on the
  floor**, where version-sensitive type errors actually surface — running them per-version
  would triple the time for no signal.
- *`noxfile.py` as the single source of truth.* CI is one job calling `uv run nox`; the
  version matrix lives in the noxfile, not in YAML. Adding the runner *removed* config
  overall rather than adding a layer — that was the bar it had to clear.
- *Version single-sourced from `src/inject_probe/__init__.py`* via `[tool.hatch.version]`,
  with `tests/test_packaging.py` asserting the installed metadata agrees. Cheap guard
  against the two drifting.

**Non-obvious.**

- `examples/` is deliberately absent from `SOURCES` in the noxfile and from mypy `files`.
  Both tools error on a missing path, and `examples/vulnerable.py` cannot exist until
  `TargetResponse` does. **Phase 1 must add `examples` back to both lists** when it lands.
- The `format` session shadows the builtin `format`. Intentional — the session name is
  the CLI surface (`nox -s format`). Ruff's `A` rules are not selected, so no `noqa` is
  needed, and adding one would trip `RUF100` (unused noqa).
- `hatchling` fails the build outright if `readme = "README.md"` points at a missing
  file, so the README had to exist before the first `uv sync` could succeed.

**Next.** Phase 1: `Target` protocol, `constants.py` + `exceptions.py`, callable adapter
and spec loader, seeded canary derivation with the shared `normalize()`, attack class 1
(direct instruction override), canary detection, and the echo-suppression test.
