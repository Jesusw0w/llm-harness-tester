"""End-to-end CLI behaviour."""

import json
from pathlib import Path

import pytest

from inject_probe.cli import main
from inject_probe.constants import EXIT_OK, EXIT_USAGE
from targets import VULNERABLE_EXAMPLE

TARGET = f"{VULNERABLE_EXAMPLE}:app"


def test_run_prints_a_table(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["run", "--target", TARGET]) == EXIT_OK
    out = capsys.readouterr().out
    assert "PROBE" in out
    assert "TOTAL" in out


def test_run_writes_a_json_report(tmp_path: Path) -> None:
    destination = tmp_path / "report.json"
    assert main(["run", "--target", TARGET, "--json", str(destination)]) == EXIT_OK
    payload = json.loads(destination.read_text())
    assert payload["schema_version"] == 1
    assert payload["corpus_version"] == "v1"
    assert payload["target"] == TARGET
    assert payload["results"]


def test_written_reports_are_byte_identical_across_runs(tmp_path: Path) -> None:
    """The `--json` output is the baseline format, so it has to be stable on disk."""
    first, second = tmp_path / "a.json", tmp_path / "b.json"
    main(["run", "--target", TARGET, "--json", str(first), "--quiet"])
    main(["run", "--target", TARGET, "--json", str(second), "--quiet"])
    assert first.read_bytes() == second.read_bytes()


def test_quiet_suppresses_the_table(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["run", "--target", TARGET, "--quiet"]) == EXIT_OK
    assert capsys.readouterr().out == ""


def test_attack_class_filter_narrows_the_run(tmp_path: Path) -> None:
    destination = tmp_path / "report.json"
    main(
        [
            "run",
            "--target",
            TARGET,
            "--attack-class",
            "direct",
            "--json",
            str(destination),
            "--quiet",
        ]
    )
    payload = json.loads(destination.read_text())
    assert set(payload["by_class"]) == {"direct"}


def test_a_bad_target_spec_is_a_usage_error(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["run", "--target", "nonsense"]) == EXIT_USAGE
    assert "error:" in capsys.readouterr().err


def test_list_probes_lists_the_corpus(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["list-probes"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "direct.ignore_previous" in out


def test_list_probes_filters_by_class(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["list-probes", "--attack-class", "direct"]) == EXIT_OK
    assert all("direct" in line for line in capsys.readouterr().out.splitlines())


def test_concurrency_below_one_is_a_usage_error() -> None:
    with pytest.raises(SystemExit) as exit_info:
        main(["run", "--target", TARGET, "--concurrency", "0"])
    assert exit_info.value.code == EXIT_USAGE


def test_an_application_that_raises_errors_one_probe_not_the_run(
    tmp_path: Path,
) -> None:
    entry = tmp_path / "raises.py"
    entry.write_text("def app(p):\n    raise RuntimeError('boom')\n")
    destination = tmp_path / "report.json"
    assert (
        main(["run", "--target", f"{entry}:app", "--json", str(destination), "--quiet"])
        == EXIT_OK
    )
    totals = json.loads(destination.read_text())["totals"]
    assert totals["errored"] == totals["attempted"] == 15
