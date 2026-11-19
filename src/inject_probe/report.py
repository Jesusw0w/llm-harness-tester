"""Report models and rendering.

The report carries **no wall-clock time and no durations**. That is deliberate:
it is what makes "same seed, same target, byte-identical report" literally true,
and it keeps a committed baseline from churning on every run. Timing information
belongs in whatever runs the tool, not in the artefact used for comparison.

The baseline file is just a saved report, so there is no second schema to keep in
step.
"""

from collections.abc import Sequence

from pydantic import BaseModel, ConfigDict, Field

from inject_probe.constants import CORPUS_VERSION
from inject_probe.detect import Outcome
from inject_probe.probe import AttackClass
from inject_probe.runner import ProbeOutcome

SCHEMA_VERSION = 1

_COLUMN_GAP = "  "


class Totals(BaseModel):
    """Attempt and success counts for a group of probes."""

    model_config = ConfigDict(frozen=True)

    attempted: int
    succeeded: int
    errored: int
    success_rate: float = Field(
        description="Successes over attempts, rounded to four places."
    )


class ProbeResult(BaseModel):
    """The outcome of one probe.

    The full payload and full response are recorded for successes and errors
    only. A blocked probe's payload is reproducible from its id and the run seed,
    so storing it would bloat every baseline for nothing.
    """

    model_config = ConfigDict(frozen=True)

    probe_id: str
    attack_class: AttackClass
    outcome: Outcome
    evidence: str
    citation: str
    prompt: str | None = None
    documents: tuple[str, ...] | None = None
    response: str | None = None
    tool_calls: tuple[str, ...] | None = None


class Report(BaseModel):
    """A complete run.

    Attributes:
        schema_version: Bumped when this model changes incompatibly.
        corpus_version: Which payload corpus produced these results.
        seed: The run seed; replaying with it reproduces the canaries exactly.
        target: The target spec the run was pointed at.
        totals: Counts across every probe.
        by_class: Counts per attack class, in taxonomy order.
        results: One entry per probe, in execution order.
    """

    model_config = ConfigDict(frozen=True)

    schema_version: int = SCHEMA_VERSION
    corpus_version: str = CORPUS_VERSION
    seed: int
    target: str
    totals: Totals
    by_class: dict[str, Totals]
    results: list[ProbeResult]


def _tally(outcomes: Sequence[ProbeOutcome]) -> Totals:
    """Count attempts, successes and errors for a group of outcomes.

    Args:
        outcomes: The outcomes to count.

    Returns:
        The tally. `success_rate` is rounded so that floating-point noise cannot
        make two otherwise identical runs differ.
    """
    attempted = len(outcomes)
    succeeded = sum(1 for o in outcomes if o.finding.outcome is Outcome.SUCCEEDED)
    errored = sum(1 for o in outcomes if o.finding.outcome is Outcome.ERROR)
    rate = round(succeeded / attempted, 4) if attempted else 0.0
    return Totals(
        attempted=attempted, succeeded=succeeded, errored=errored, success_rate=rate
    )


def build_report(outcomes: Sequence[ProbeOutcome], *, seed: int, target: str) -> Report:
    """Assemble a report from a completed run.

    Args:
        outcomes: What the runner produced, in execution order.
        seed: The seed the run used.
        target: The target spec, recorded so a report identifies what it tested.

    Returns:
        The report.
    """
    results = [
        ProbeResult(
            probe_id=outcome.probe.id,
            attack_class=outcome.probe.attack_class,
            outcome=outcome.finding.outcome,
            evidence=outcome.finding.evidence,
            citation=outcome.probe.citation,
            # Full detail for anything a reader has to act on.
            prompt=(
                outcome.probe.prompt
                if outcome.finding.outcome is not Outcome.BLOCKED
                else None
            ),
            documents=(
                outcome.probe.documents
                if outcome.finding.outcome is not Outcome.BLOCKED
                and outcome.probe.documents
                else None
            ),
            response=(
                outcome.response.text
                if outcome.response is not None
                and outcome.finding.outcome is not Outcome.BLOCKED
                else None
            ),
            tool_calls=(
                outcome.response.tool_calls
                if outcome.response is not None and outcome.response.tool_calls
                else None
            ),
        )
        for outcome in outcomes
    ]

    by_class = {
        attack_class.value: _tally(
            [o for o in outcomes if o.probe.attack_class is attack_class]
        )
        for attack_class in AttackClass
        if any(o.probe.attack_class is attack_class for o in outcomes)
    }

    return Report(
        seed=seed,
        target=target,
        totals=_tally(outcomes),
        by_class=by_class,
        results=results,
    )


def render_table(report: Report) -> str:
    """Render a report as a plain-text table.

    Hand-rolled rather than pulled from a table library: the runtime dependency
    list is `httpx` and `pydantic`, and one column-width calculation does not
    justify a third.

    Args:
        report: The report to render.

    Returns:
        The rendered table, ready to print.
    """
    headers = ("PROBE", "CLASS", "OUTCOME")
    rows = [
        (result.probe_id, result.attack_class.value, result.outcome.value)
        for result in report.results
    ]
    widths = [
        max(len(header), *(len(row[index]) for row in rows)) if rows else len(header)
        for index, header in enumerate(headers)
    ]

    def line(cells: tuple[str, ...]) -> str:
        return _COLUMN_GAP.join(
            cell.ljust(width) for cell, width in zip(cells, widths, strict=True)
        ).rstrip()

    out = [line(headers), _COLUMN_GAP.join("-" * width for width in widths)]
    out.extend(line(row) for row in rows)

    out.append("")
    for name, totals in report.by_class.items():
        out.append(
            f"{name:<10} {totals.succeeded}/{totals.attempted} succeeded "
            f"({totals.success_rate:.1%})"
        )
    out.append(
        f"{'TOTAL':<10} {report.totals.succeeded}/{report.totals.attempted} succeeded "
        f"({report.totals.success_rate:.1%})"
    )
    if report.totals.errored:
        out.append(
            f"{report.totals.errored} probe(s) errored (unreachable, non-2xx, "
            "or the target raised); see `evidence` in the --json report."
        )
    return "\n".join(out)


def to_json(report: Report) -> str:
    """Serialise a report to JSON.

    Args:
        report: The report to serialise.

    Returns:
        Indented JSON with a trailing newline, stable for the same seed and
        target.
    """
    return report.model_dump_json(indent=2) + "\n"
