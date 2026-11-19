"""Regression comparison against a recorded run.

Absolute thresholds are useless for this tool. No real LLM application scores
zero, so a gate that fails whenever any probe succeeds is red from day one and
gets ignored — and a gate everybody ignores is worse than no gate at all.

The useful question is not "are there vulnerabilities" but "did this change make
it worse". That is a comparison against a recorded state:

* was blocked, now succeeded -> **regression**, the build fails
* was succeeded, now blocked -> fixed, reported and welcomed
* absent from the baseline  -> new, reported; fails only with `--fail-on-new`,
  and only when the new probe succeeded
* errored in this run       -> the build fails: the comparison is incomplete,
  and an outage must never read as a clean run

A baseline is just a saved report, so there is no second schema to keep in step
and `--json` doubles as the recording command.
"""

import json
from dataclasses import dataclass
from pathlib import Path

from inject_probe.detect import Outcome
from inject_probe.exceptions import ConfigError
from inject_probe.report import SCHEMA_VERSION, Report


@dataclass(frozen=True, slots=True)
class Baseline:
    """A recorded run, reduced to what a comparison needs.

    Attributes:
        corpus_version: The corpus that produced it. Comparing across corpus
            versions is meaningless, so this travels with the outcomes.
        outcomes: The recorded outcome per probe id.
    """

    corpus_version: str
    outcomes: dict[str, Outcome]


@dataclass(frozen=True, slots=True)
class Comparison:
    """The difference between a run and its baseline.

    Attributes:
        regressions: Probes that were blocked and now succeed.
        fixed: Probes that succeeded and are now blocked.
        new: Probes absent from the baseline that succeeded in this run.
        new_blocked: Probes absent from the baseline that were blocked.
        errored: Probes that errored in this run, so could not be compared.
        unchanged: How many probes kept their previous outcome.
    """

    regressions: tuple[str, ...]
    fixed: tuple[str, ...]
    new: tuple[str, ...]
    new_blocked: tuple[str, ...]
    errored: tuple[str, ...]
    unchanged: int

    def failed(self, *, fail_on_new: bool) -> bool:
        """Whether this comparison should fail the build.

        Args:
            fail_on_new: Also fail when a probe absent from the baseline
                succeeded.

        Returns:
            True if the run should exit non-zero. Any errored probe fails it: a
            probe that could not be compared might have regressed, and passing
            would let an expired token or a dead endpoint go green.
        """
        return (
            bool(self.regressions)
            or bool(self.errored)
            or (fail_on_new and bool(self.new))
        )


def load_baseline(path: Path) -> Baseline:
    """Read a recorded report and reduce it to what a comparison needs.

    Args:
        path: The baseline file, which is an ordinary `--json` report.

    Returns:
        The recorded corpus version and per-probe outcomes.

    Raises:
        ConfigError: The file is missing, unreadable, not a report, or was
            produced by a different schema version.
    """
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise ConfigError(f"cannot read baseline {path}: {error}") from error
    except json.JSONDecodeError as error:
        raise ConfigError(f"baseline {path} is not valid JSON: {error}") from error

    if not isinstance(payload, dict) or "results" not in payload:
        raise ConfigError(f"baseline {path} is not an inject-probe report")

    recorded_schema = payload.get("schema_version")
    if recorded_schema != SCHEMA_VERSION:
        raise ConfigError(
            f"baseline {path} has schema_version {recorded_schema}, "
            f"this build writes {SCHEMA_VERSION}; re-record it"
        )

    try:
        outcomes = {
            result["probe_id"]: Outcome(result["outcome"])
            for result in payload["results"]
        }
    except (KeyError, TypeError, ValueError) as error:
        raise ConfigError(
            f"baseline {path} has a malformed result entry: {error!r}"
        ) from error

    return Baseline(
        corpus_version=str(payload.get("corpus_version", "")),
        outcomes=outcomes,
    )


def compare(report: Report, baseline: Baseline, baseline_path: Path) -> Comparison:
    """Compare a run against a recorded baseline.

    Errored probes are never compared: a target that could not be reached tells
    you nothing about whether it regressed, so they are neither fixed nor
    regressed. They are collected in `errored` instead, which fails the gate.

    Args:
        report: This run.
        baseline: The recorded baseline.
        baseline_path: Where the baseline came from, for error messages.

    Returns:
        The comparison.

    Raises:
        ConfigError: The baseline was recorded against a different corpus
            version. Refused rather than warned about — a v1 baseline compared
            against a v2 corpus produces confident nonsense. Re-record instead.
    """
    if baseline.corpus_version != report.corpus_version:
        raise ConfigError(
            f"baseline {baseline_path} was recorded against corpus "
            f"{baseline.corpus_version!r}, this run used "
            f"{report.corpus_version!r}; re-record the baseline"
        )

    regressions: list[str] = []
    fixed: list[str] = []
    new: list[str] = []
    new_blocked: list[str] = []
    errored: list[str] = []
    unchanged = 0

    for result in report.results:
        if result.outcome is Outcome.ERROR:
            errored.append(result.probe_id)
            continue
        previous = baseline.outcomes.get(result.probe_id)
        if previous is None:
            (new if result.outcome is Outcome.SUCCEEDED else new_blocked).append(
                result.probe_id
            )
        elif previous is Outcome.BLOCKED and result.outcome is Outcome.SUCCEEDED:
            regressions.append(result.probe_id)
        elif previous is Outcome.SUCCEEDED and result.outcome is Outcome.BLOCKED:
            fixed.append(result.probe_id)
        else:
            unchanged += 1

    return Comparison(
        regressions=tuple(regressions),
        fixed=tuple(fixed),
        new=tuple(new),
        new_blocked=tuple(new_blocked),
        errored=tuple(errored),
        unchanged=unchanged,
    )


def render_comparison(comparison: Comparison, baseline_path: Path) -> str:
    """Render a comparison for the terminal.

    Args:
        comparison: The comparison to render.
        baseline_path: The baseline it was made against.

    Returns:
        The rendered summary.
    """
    lines = [f"\nAgainst baseline {baseline_path}:"]
    for probe_id in comparison.regressions:
        lines.append(f"  REGRESSION  {probe_id}  (was blocked, now succeeds)")
    for probe_id in comparison.fixed:
        lines.append(f"  fixed       {probe_id}")
    for probe_id in comparison.new:
        lines.append(f"  NEW         {probe_id}  (not in baseline, succeeded)")
    for probe_id in comparison.new_blocked:
        lines.append(f"  new         {probe_id}  (not in baseline, blocked)")
    for probe_id in comparison.errored:
        lines.append(f"  ERROR       {probe_id}  (errored, could not be compared)")
    lines.append(
        f"  {len(comparison.regressions)} regression(s), "
        f"{len(comparison.fixed)} fixed, "
        f"{len(comparison.new) + len(comparison.new_blocked)} new, "
        f"{len(comparison.errored)} errored, "
        f"{comparison.unchanged} unchanged."
    )
    return "\n".join(lines)
