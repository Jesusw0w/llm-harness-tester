"""Regression gating: a new failure fails the run, a fixed one does not."""

import json
from pathlib import Path

import pytest

from inject_probe.attacks import build_probes
from inject_probe.baseline import Baseline, compare, load_baseline
from inject_probe.cli import main
from inject_probe.constants import EXIT_OK, EXIT_REGRESSION, EXIT_USAGE
from inject_probe.detect import Outcome
from inject_probe.exceptions import ConfigError
from inject_probe.probe import AttackClass
from inject_probe.report import Report, build_report, to_json
from inject_probe.runner import run
from inject_probe.target import Target
from targets import (
    VULNERABLE_EXAMPLE,
    RefusingTarget,
    UnreachableTarget,
    vulnerable_target,
)

TARGET = f"{VULNERABLE_EXAMPLE}:app"


def _report(target: Target, seed: int = 0) -> Report:
    probes = build_probes(seed=seed)
    return build_report(run(target, probes, concurrency=2), seed=seed, target="stub")


def _baseline_from(outcomes: dict[str, Outcome]) -> Baseline:
    return Baseline(corpus_version="v1", outcomes=outcomes)


def test_a_new_failure_is_a_regression() -> None:
    """Everything blocked before; the vulnerable target now succeeds."""
    report = _report(vulnerable_target())
    previously_clean = _baseline_from(
        {result.probe_id: Outcome.BLOCKED for result in report.results}
    )
    comparison = compare(report, previously_clean, Path("b.json"))
    assert comparison.regressions
    assert comparison.failed(fail_on_new=False)


def test_a_fixed_failure_does_not_fail_the_run() -> None:
    """Everything succeeded before; a refusing target now blocks it all."""
    report = _report(RefusingTarget())
    previously_broken = _baseline_from(
        {result.probe_id: Outcome.SUCCEEDED for result in report.results}
    )
    comparison = compare(report, previously_broken, Path("b.json"))
    assert comparison.fixed
    assert not comparison.regressions
    assert not comparison.failed(fail_on_new=False)


def test_an_unchanged_run_is_clean() -> None:
    report = _report(vulnerable_target())
    same = _baseline_from({r.probe_id: r.outcome for r in report.results})
    comparison = compare(report, same, Path("b.json"))
    assert not comparison.regressions
    assert not comparison.fixed
    assert comparison.unchanged == len(report.results)


def test_a_new_succeeding_probe_fails_only_with_the_flag() -> None:
    report = _report(vulnerable_target())
    empty = _baseline_from({})
    comparison = compare(report, empty, Path("b.json"))
    assert comparison.new
    assert not comparison.failed(fail_on_new=False)
    assert comparison.failed(fail_on_new=True)


def test_a_new_blocked_probe_never_fails() -> None:
    report = _report(RefusingTarget())
    comparison = compare(report, _baseline_from({}), Path("b.json"))
    assert comparison.new_blocked
    assert not comparison.new
    assert not comparison.failed(fail_on_new=True)


def test_errored_probes_are_not_compared_and_fail_the_gate() -> None:
    """An outage must read neither as every probe fixed nor as a clean run."""
    report = _report(UnreachableTarget())
    previously_broken = _baseline_from(
        {result.probe_id: Outcome.SUCCEEDED for result in report.results}
    )
    comparison = compare(report, previously_broken, Path("b.json"))
    assert not comparison.fixed
    assert not comparison.regressions
    assert len(comparison.errored) == len(report.results)
    assert comparison.failed(fail_on_new=False)


def test_a_single_errored_probe_fails_the_cli_gate(tmp_path: Path) -> None:
    """Stricter by design: one probe that could not be compared fails the build."""
    baseline = tmp_path / "baseline.json"
    assert main(["run", "--target", TARGET, "--json", str(baseline), "--quiet"]) == 0
    entry = tmp_path / "flaky.py"
    entry.write_text(
        "import importlib.util\n"
        "spec = importlib.util.spec_from_file_location(\n"
        f"    'v', {str(VULNERABLE_EXAMPLE)!r}\n"
        ")\n"
        "v = importlib.util.module_from_spec(spec)\n"
        "spec.loader.exec_module(v)\n"
        "def app(prompt, documents=()):\n"
        "    if 'ROT13' in prompt:\n"
        "        raise RuntimeError('flaky')\n"
        "    return v.app(prompt, documents)\n"
    )
    argv = ["run", "--target", f"{entry}:app", "--baseline", str(baseline)]
    assert main([*argv, "--quiet"]) == EXIT_REGRESSION


def test_a_corpus_version_mismatch_is_refused() -> None:
    report = _report(RefusingTarget())
    stale = Baseline(corpus_version="v0", outcomes={})
    with pytest.raises(ConfigError, match="re-record the baseline"):
        compare(report, stale, Path("b.json"))


def test_loading_rejects_a_foreign_schema_version(tmp_path: Path) -> None:
    path = tmp_path / "b.json"
    path.write_text(json.dumps({"schema_version": 99, "results": []}))
    with pytest.raises(ConfigError, match="schema_version"):
        load_baseline(path)


def test_loading_rejects_a_non_report(tmp_path: Path) -> None:
    path = tmp_path / "b.json"
    path.write_text(json.dumps({"something": "else"}))
    with pytest.raises(ConfigError, match="not an inject-probe report"):
        load_baseline(path)


def test_loading_rejects_invalid_json(tmp_path: Path) -> None:
    path = tmp_path / "b.json"
    path.write_text("{[")
    with pytest.raises(ConfigError, match="not valid JSON"):
        load_baseline(path)


def test_loading_rejects_a_missing_file(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="cannot read baseline"):
        load_baseline(tmp_path / "absent.json")


# --- End to end through the CLI -------------------------------------------------


def test_cli_exits_zero_against_its_own_baseline(tmp_path: Path) -> None:
    baseline = tmp_path / "baseline.json"
    assert main(["run", "--target", TARGET, "--json", str(baseline), "--quiet"]) == (
        EXIT_OK
    )
    assert (
        main(["run", "--target", TARGET, "--baseline", str(baseline), "--quiet"])
        == EXIT_OK
    )


def test_cli_exits_non_zero_on_a_regression(tmp_path: Path) -> None:
    """Record a clean baseline from a refusing target, then run the vulnerable one."""
    baseline = tmp_path / "baseline.json"
    clean = build_report(
        run(RefusingTarget(), build_probes(seed=0), concurrency=2),
        seed=0,
        target=TARGET,
    )
    baseline.write_text(to_json(clean))

    assert (
        main(["run", "--target", TARGET, "--baseline", str(baseline), "--quiet"])
        == EXIT_REGRESSION
    )


def test_cli_reports_regressions_on_stdout(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    baseline = tmp_path / "baseline.json"
    clean = build_report(
        run(RefusingTarget(), build_probes(seed=0), concurrency=2),
        seed=0,
        target=TARGET,
    )
    baseline.write_text(to_json(clean))

    main(["run", "--target", TARGET, "--baseline", str(baseline)])
    out = capsys.readouterr().out
    assert "REGRESSION" in out
    assert "direct.ignore_previous" in out


def test_cli_reports_a_missing_baseline_as_a_usage_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert (
        main(
            [
                "run",
                "--target",
                TARGET,
                "--baseline",
                str(tmp_path / "absent.json"),
                "--quiet",
            ]
        )
        == EXIT_USAGE
    )
    assert "error:" in capsys.readouterr().err


def test_a_narrowed_run_does_not_regress_against_a_full_baseline(
    tmp_path: Path,
) -> None:
    """Filtering by attack class must not read as the other classes being fixed."""
    baseline = tmp_path / "baseline.json"
    main(["run", "--target", TARGET, "--json", str(baseline), "--quiet"])
    assert (
        main(
            [
                "run",
                "--target",
                TARGET,
                "--attack-class",
                AttackClass.DIRECT.value,
                "--baseline",
                str(baseline),
                "--quiet",
            ]
        )
        == EXIT_OK
    )


def test_writing_the_report_over_its_own_baseline_still_compares_the_old_one(
    tmp_path: Path,
) -> None:
    """`--json X --baseline X` must compare before overwriting, not after."""
    path = tmp_path / "baseline.json"
    echo = Path(__file__).parent.parent / "examples" / "echoing.py"
    assert (
        main(["run", "--target", f"{echo}:app", "--json", str(path), "--quiet"])
        == EXIT_OK
    )
    argv = ["run", "--target", TARGET, "--json", str(path), "--baseline", str(path)]
    assert main([*argv, "--quiet"]) == EXIT_REGRESSION


def test_a_missing_baseline_is_rejected_before_the_run(tmp_path: Path) -> None:
    missing = tmp_path / "missing.json"
    assert (
        main(["run", "--target", TARGET, "--baseline", str(missing), "--quiet"])
        == EXIT_USAGE
    )


def test_a_malformed_baseline_entry_is_a_config_error(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text(json.dumps({"schema_version": 1, "results": [{"x": 1}]}))
    with pytest.raises(ConfigError, match="malformed result entry"):
        load_baseline(path)
