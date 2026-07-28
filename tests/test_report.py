"""Report assembly, determinism, and what a report is allowed to contain."""

import json

from inject_probe.attacks import build_probes
from inject_probe.detect import Outcome
from inject_probe.report import build_report, render_table, to_json
from inject_probe.runner import run
from inject_probe.target import Target
from targets import (
    EchoTarget,
    RefusingTarget,
    UnreachableTarget,
    vulnerable_target,
)


def _report_for(target: Target, seed: int = 0, concurrency: int = 2) -> str:
    probes = build_probes(seed=seed)
    outcomes = run(target, probes, concurrency=concurrency)
    return to_json(build_report(outcomes, seed=seed, target="stub"))


def test_same_seed_produces_byte_identical_reports() -> None:
    """The property that makes a committed baseline stable."""
    assert _report_for(RefusingTarget()) == _report_for(RefusingTarget())


def test_vulnerable_report_is_byte_identical_across_runs() -> None:
    """Same, but on the path where results actually vary by probe."""
    assert _report_for(vulnerable_target()) == _report_for(vulnerable_target())


def test_a_different_seed_changes_the_report() -> None:
    """If it did not, the seed would not be doing anything."""
    assert _report_for(RefusingTarget(), seed=1) != _report_for(
        RefusingTarget(), seed=2
    )


def test_report_contains_no_wall_clock_fields() -> None:
    """Timestamps would break byte-identity and churn every baseline diff."""
    payload = json.loads(_report_for(RefusingTarget()))
    forbidden = ("timestamp", "started", "finished", "duration", "elapsed", "time")
    flattened = json.dumps(payload).lower()
    for field in forbidden:
        assert f'"{field}' not in flattened


def test_successes_record_the_exact_payload_and_response() -> None:
    payload = json.loads(_report_for(vulnerable_target()))
    successes = [r for r in payload["results"] if r["outcome"] == "succeeded"]
    assert successes
    for result in successes:
        assert result["prompt"]
        assert result["response"]
        assert result["citation"]


def test_blocked_probes_omit_the_payload() -> None:
    """A blocked probe is reproducible from its id and seed; storing it is bloat."""
    payload = json.loads(_report_for(RefusingTarget()))
    blocked = [r for r in payload["results"] if r["outcome"] == "blocked"]
    assert blocked
    assert all(r["prompt"] is None and r["response"] is None for r in blocked)


def test_totals_break_down_by_attack_class() -> None:
    payload = json.loads(_report_for(vulnerable_target()))
    assert payload["by_class"]
    assert (
        sum(c["attempted"] for c in payload["by_class"].values())
        == (payload["totals"]["attempted"])
    )


def test_echo_target_reports_a_zero_success_rate() -> None:
    payload = json.loads(_report_for(EchoTarget()))
    assert payload["totals"]["succeeded"] == 0
    assert payload["totals"]["success_rate"] == 0.0


def test_table_renders_every_probe_and_a_total() -> None:
    probes = build_probes(seed=0)
    outcomes = run(RefusingTarget(), probes, concurrency=2)
    table = render_table(build_report(outcomes, seed=0, target="stub"))
    for probe in probes:
        assert probe.id in table
    assert "TOTAL" in table


def test_concurrency_does_not_change_the_report() -> None:
    """Guards the choice of `map` over `as_completed`.

    `as_completed` would interleave results by timing, making reports
    non-deterministic under concurrency while passing every serial test.
    """
    serial = _report_for(vulnerable_target(), concurrency=1)
    for concurrency in (2, 4, 16):
        assert _report_for(vulnerable_target(), concurrency=concurrency) == serial


def test_runner_preserves_probe_order() -> None:
    probes = build_probes(seed=0)
    outcomes = run(RefusingTarget(), probes, concurrency=4)
    assert [o.probe.id for o in outcomes] == [p.id for p in probes]


def test_runner_handles_an_empty_corpus() -> None:
    assert run(RefusingTarget(), [], concurrency=4) == []


def test_error_outcomes_are_counted_separately() -> None:
    payload = json.loads(_report_for(RefusingTarget()))
    assert payload["totals"]["errored"] == 0
    assert all(r["outcome"] != Outcome.ERROR.value for r in payload["results"])


def test_an_unreachable_target_errors_rather_than_aborting_the_run() -> None:
    """One dead probe must not lose the results of every other probe."""
    payload = json.loads(_report_for(UnreachableTarget()))
    assert payload["totals"]["attempted"] == len(payload["results"])
    assert payload["totals"]["errored"] == payload["totals"]["attempted"]
    assert payload["totals"]["succeeded"] == 0
    assert all(r["outcome"] == Outcome.ERROR.value for r in payload["results"])
    assert all("connection refused" in r["evidence"] for r in payload["results"])
