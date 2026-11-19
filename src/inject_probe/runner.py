"""Executing a corpus against a target.

Bounded concurrency comes from a thread pool rather than async, which keeps the
`Target` protocol a plain method that users can implement without restructuring
their application.

There is no retry logic here. Retries belong to the transport that knows what a
transient failure looks like — `httpx.HTTPTransport(retries=...)` for the HTTP
adapters. Retrying at this level would risk re-sending a probe to a target that
answered perfectly well, which would corrupt the result rather than repair it.
"""

from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from inject_probe.constants import DEFAULT_CONCURRENCY
from inject_probe.detect import Finding, Outcome, detect
from inject_probe.exceptions import TargetError
from inject_probe.probe import Probe
from inject_probe.target import Target, TargetResponse


@dataclass(frozen=True, slots=True)
class ProbeOutcome:
    """One probe, what came back, and the verdict.

    Attributes:
        probe: The probe that was sent.
        finding: The verdict.
        response: What the target replied, or `None` if it could not be reached.
    """

    probe: Probe
    finding: Finding
    response: TargetResponse | None


def _execute(target: Target, probe: Probe) -> ProbeOutcome:
    """Send one probe and judge the reply, turning transport failure into a result.

    Args:
        target: The system under test.
        probe: The probe to send.

    Returns:
        The outcome. A target that could not be reached yields `Outcome.ERROR`
        rather than raising, so one unreachable probe cannot abort the run.
    """
    try:
        response = target.send(probe.prompt, documents=probe.documents)
    except TargetError as error:
        return ProbeOutcome(
            probe=probe,
            finding=Finding(outcome=Outcome.ERROR, evidence=str(error)),
            response=None,
        )
    return ProbeOutcome(probe=probe, finding=detect(probe, response), response=response)


def run(
    target: Target,
    probes: Sequence[Probe],
    *,
    concurrency: int = DEFAULT_CONCURRENCY,
) -> list[ProbeOutcome]:
    """Execute every probe against the target.

    Results come back in the order the probes were given, not the order they
    finished. That ordering is the other half of what makes two runs with the
    same seed produce byte-identical reports.

    Args:
        target: The system under test.
        probes: The corpus to execute.
        concurrency: Maximum probes in flight at once.

    Returns:
        One outcome per probe, in input order.

    Raises:
        ValueError: `concurrency` is not at least 1.
    """
    if concurrency < 1:
        raise ValueError(f"concurrency must be at least 1, got {concurrency}")
    if not probes:
        return []
    with ThreadPoolExecutor(max_workers=min(concurrency, len(probes))) as pool:
        return list(pool.map(lambda probe: _execute(target, probe), probes))
