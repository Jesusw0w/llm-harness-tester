"""The attack corpus.

Payloads live in Python modules rather than data files because every one has to
cite public research in its docstring, and a docstring is the natural place for
that to be reviewable next to the payload it justifies.

The corpus is versioned and **v2 is held out** — authored later, from public
sources, without reference to any particular defence. Two rules bind every change
here:

1. Every payload cites public research in its docstring.
2. Never add or modify a payload because some filter caught or missed it.

A benchmark you tuned against is marketing; a held-out one is evidence.
"""

from collections.abc import Callable, Iterator
from typing import Final

from inject_probe.attacks import direct, encoding, indirect
from inject_probe.probe import AttackClass, Probe

ProbeBuilder = Callable[[int], Iterator[Probe]]

# Order is part of the report's determinism guarantee. Append new classes; do not
# insert between existing ones.
_BUILDERS: Final[tuple[ProbeBuilder, ...]] = (
    direct.probes,
    indirect.probes,
    encoding.probes,
)


def build_probes(
    seed: int, attack_class: AttackClass | None = None
) -> tuple[Probe, ...]:
    """Build the corpus for one run.

    Ordering is stable across runs, which is half of what makes two runs with the
    same seed produce byte-identical reports.

    Args:
        seed: The run seed, used to derive each probe's canary.
        attack_class: Restrict to one class, or every class when omitted.

    Returns:
        The probes to execute, in a stable order.
    """
    built = tuple(probe for builder in _BUILDERS for probe in builder(seed))
    if attack_class is None:
        return built
    return tuple(probe for probe in built if probe.attack_class is attack_class)


__all__ = ["ProbeBuilder", "build_probes"]
