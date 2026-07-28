"""Targets that did nothing must score zero, and a vulnerable one must not.

This is the subtlest bug in the tool: if an echoing target registers successes,
every success rate the harness reports is inflated, and nothing else about the
output can be trusted.
"""

from pathlib import Path

from inject_probe.adapters import load_target
from inject_probe.attacks import build_probes
from inject_probe.detect import Outcome
from inject_probe.probe import AttackClass
from targets import (
    EchoTarget,
    RefusingTarget,
    WhitespaceManglingEchoTarget,
    run_probes,
)

VULNERABLE_EXAMPLE = Path(__file__).parent.parent / "examples" / "vulnerable.py"


def test_echoing_target_scores_zero() -> None:
    findings = run_probes(EchoTarget(), build_probes(seed=0))
    assert findings
    assert all(f.outcome is Outcome.BLOCKED for f in findings)


def test_whitespace_mangling_echo_scores_zero() -> None:
    """The adversarial echo: output already in the detector's normalised form."""
    findings = run_probes(WhitespaceManglingEchoTarget(), build_probes(seed=0))
    assert findings
    assert all(f.outcome is Outcome.BLOCKED for f in findings)


def test_refusing_target_scores_zero() -> None:
    findings = run_probes(RefusingTarget(), build_probes(seed=0))
    assert findings
    assert all(f.outcome is Outcome.BLOCKED for f in findings)


def test_echo_suppression_holds_across_seeds() -> None:
    """A canary that happened to be echo-proof for one seed proves nothing."""
    for seed in range(25):
        findings = run_probes(EchoTarget(), build_probes(seed=seed))
        assert all(f.outcome is Outcome.BLOCKED for f in findings), (
            f"echo registered a success at seed {seed}"
        )


def test_vulnerable_example_registers_the_expected_successes() -> None:
    """The other half: a detector that never fires is also useless."""
    target = load_target(f"{VULNERABLE_EXAMPLE}:app")
    probes = build_probes(seed=0, attack_class=AttackClass.DIRECT)
    findings = run_probes(target, probes)

    assert findings
    assert all(f.outcome is Outcome.SUCCEEDED for f in findings)
