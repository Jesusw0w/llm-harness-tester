"""Stub targets covering the behaviours the detector has to tell apart."""

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

from inject_probe.adapters import load_target
from inject_probe.detect import Finding, detect
from inject_probe.exceptions import TargetError
from inject_probe.probe import Probe
from inject_probe.target import Target, TargetResponse

VULNERABLE_EXAMPLE = Path(__file__).parent.parent / "examples" / "vulnerable.py"


@dataclass(frozen=True, slots=True)
class EchoTarget:
    """Mirrors its entire input back verbatim.

    The single most important stub in the suite. An echoing target reproduces
    every canary fragment the payload contained, so any detector that looks for
    the canary naively scores a perfect success rate against a system that did
    nothing at all.
    """

    def send(self, prompt: str, *, documents: Sequence[str] = ()) -> TargetResponse:
        """Return the prompt and documents unchanged."""
        return TargetResponse(text="\n".join([*documents, prompt]))


@dataclass(frozen=True, slots=True)
class WhitespaceManglingEchoTarget:
    """Echoes its input with every whitespace character removed.

    The adversarial case for `canary.normalize`: it produces exactly the string
    the detector normalises towards. If the fragment separator were whitespace,
    this target would manufacture a canary hit out of a pure echo.
    """

    def send(self, prompt: str, *, documents: Sequence[str] = ()) -> TargetResponse:
        """Return the input with all whitespace stripped."""
        return TargetResponse(text="".join("".join([*documents, prompt]).split()))


@dataclass(frozen=True, slots=True)
class RefusingTarget:
    """Ignores its input entirely and answers with a fixed refusal."""

    def send(self, prompt: str, *, documents: Sequence[str] = ()) -> TargetResponse:
        """Return a constant refusal."""
        return TargetResponse(text="I can't help with that request.")


@dataclass(frozen=True, slots=True)
class UnreachableTarget:
    """Always fails at the transport layer."""

    def send(self, prompt: str, *, documents: Sequence[str] = ()) -> TargetResponse:
        """Raise as though the application could not be reached.

        Raises:
            TargetError: Always.
        """
        raise TargetError("connection refused")


def vulnerable_target() -> Target:
    """Load the deliberately vulnerable example application.

    Returns:
        The example app, wrapped as a target.
    """
    return load_target(f"{VULNERABLE_EXAMPLE}:app")


def run_probes(target: Target, probes: Iterable[Probe]) -> list[Finding]:
    """Send each probe to a target and judge the reply.

    Serial and without the runner's error handling, so a test sees any
    exception directly rather than as an `error` outcome.

    Args:
        target: The system under test.
        probes: The probes to send.

    Returns:
        One finding per probe, in the order given.
    """
    return [
        detect(probe, target.send(probe.prompt, documents=probe.documents))
        for probe in probes
    ]
