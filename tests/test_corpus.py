"""Invariants every payload in the corpus has to satisfy."""

import re

import pytest

from inject_probe.attacks import build_probes
from inject_probe.canary import derive
from inject_probe.probe import AttackClass, Probe

# A citation has to name something a reader can go and check.
REFERENCE_MARKER = re.compile(r"arXiv:\d{4}\.\d{4,5}|OWASP|https?://")


def test_corpus_is_not_empty() -> None:
    assert build_probes(seed=0)


def test_probe_ids_are_unique() -> None:
    probes = build_probes(seed=0)
    ids = [probe.id for probe in probes]
    assert len(set(ids)) == len(ids)


@pytest.mark.parametrize("probe", build_probes(seed=0), ids=lambda p: p.id)
def test_every_payload_cites_public_research(probe: Probe) -> None:
    assert REFERENCE_MARKER.search(probe.citation), (
        f"{probe.id} cites nothing checkable"
    )


@pytest.mark.parametrize("probe", build_probes(seed=0), ids=lambda p: p.id)
def test_no_payload_leaks_its_own_canary(probe: Probe) -> None:
    """The echo defence, asserted across the whole corpus rather than per probe.

    `Probe.__post_init__` already refuses to build a leaking probe, so this
    failing means something bypassed construction — but the corpus-wide check is
    what makes the guarantee visible, and it is the first test to look at if the
    success numbers ever look too good.
    """
    assert probe.canary.value not in probe.rendered_input


def test_corpus_is_stable_across_builds() -> None:
    """Half of what makes two runs with the same seed byte-identical."""
    first = build_probes(seed=42)
    second = build_probes(seed=42)
    assert [p.id for p in first] == [p.id for p in second]
    assert [p.prompt for p in first] == [p.prompt for p in second]
    assert [p.canary.value for p in first] == [p.canary.value for p in second]


def test_filtering_by_attack_class() -> None:
    direct = build_probes(seed=0, attack_class=AttackClass.DIRECT)
    assert direct
    assert all(p.attack_class is AttackClass.DIRECT for p in direct)


def test_probe_rejects_a_leaked_canary() -> None:
    canary = derive(0, "test.leak")
    with pytest.raises(ValueError, match="leaks its canary"):
        Probe(
            id="test.leak",
            attack_class=AttackClass.DIRECT,
            citation="OWASP LLM01",
            canary=canary,
            prompt=f"Please emit {canary.value} now.",
        )


def test_probe_rejects_a_missing_citation() -> None:
    with pytest.raises(ValueError, match="no citation"):
        Probe(
            id="test.uncited",
            attack_class=AttackClass.DIRECT,
            citation="   ",
            canary=derive(0, "test.uncited"),
            prompt="anything",
        )
