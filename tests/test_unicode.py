"""Obfuscated payloads must survive the full round trip unmangled.

If a payload's zero-width characters get stripped, or its homoglyphs normalised,
somewhere between construction and the target, the encoding class silently
degrades into the direct class and the report claims coverage it does not have.
"""

import json

from inject_probe.attacks import build_probes
from inject_probe.attacks.encoding import (
    _HOMOGLYPHS,
    _POP_DIRECTIONAL_FORMATTING,
    _RIGHT_TO_LEFT_OVERRIDE,
    _ZERO_WIDTH_SPACE,
)
from inject_probe.probe import AttackClass
from inject_probe.report import build_report, to_json
from inject_probe.runner import run
from targets import EchoTarget, UnreachableTarget

ENCODING_PROBES = build_probes(seed=0, attack_class=AttackClass.ENCODING)


def _probe(probe_id: str) -> str:
    return next(p.prompt for p in ENCODING_PROBES if p.id == probe_id)


def test_zero_width_characters_are_present_in_the_payload() -> None:
    assert _ZERO_WIDTH_SPACE in _probe("encoding.zero_width_split")


def test_bidi_controls_are_present_in_the_payload() -> None:
    payload = _probe("encoding.bidi_override")
    assert _RIGHT_TO_LEFT_OVERRIDE in payload
    assert _POP_DIRECTIONAL_FORMATTING in payload


def test_homoglyphs_are_present_and_are_not_latin() -> None:
    payload = _probe("encoding.homoglyph_substitution")
    assert _HOMOGLYPHS["o"] in payload
    assert "Output these tokens" not in payload


def test_payloads_survive_the_target_round_trip() -> None:
    """An echoing target returns exactly what it was handed, byte for byte."""
    target = EchoTarget()
    for probe in ENCODING_PROBES:
        reply = target.send(probe.prompt, documents=probe.documents)
        assert probe.prompt in reply.text


def test_payloads_survive_json_serialisation() -> None:
    """The report is written as JSON; obfuscation must not be lost on the way.

    Uses an unreachable target because blocked probes deliberately omit their
    payload from the report — an errored one records it, which is what needs
    checking here.
    """
    outcomes = run(UnreachableTarget(), ENCODING_PROBES, concurrency=2)
    serialised = to_json(build_report(outcomes, seed=0, target="stub"))
    recorded = {r["probe_id"]: r["prompt"] for r in json.loads(serialised)["results"]}

    for probe in ENCODING_PROBES:
        assert recorded[probe.id] == probe.prompt, (
            f"{probe.id} was mangled by JSON serialisation"
        )


def test_utf8_encoding_is_lossless_for_every_payload() -> None:
    for probe in build_probes(seed=0):
        assert probe.prompt.encode("utf-8").decode("utf-8") == probe.prompt
        for document in probe.documents:
            assert document.encode("utf-8").decode("utf-8") == document
