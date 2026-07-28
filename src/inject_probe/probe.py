"""A single test case: one payload, its metadata, and its canary."""

from dataclasses import dataclass
from enum import StrEnum

from inject_probe.canary import Canary, normalize


class AttackClass(StrEnum):
    """The taxonomy v1 covers.

    Tool-call hijacking, system-prompt extraction and multi-turn escalation are
    deliberately absent — they are v2 scope boundaries, not a backlog.
    """

    DIRECT = "direct"
    INDIRECT = "indirect"
    ENCODING = "encoding"


@dataclass(frozen=True, slots=True)
class Probe:
    """One payload, rendered and ready to send.

    Attributes:
        id: Stable identifier, e.g. ``direct.ignore_previous``. Used to derive
            the canary and to key baseline comparisons, so renaming one is a
            breaking change to any recorded baseline.
        attack_class: Which class this probe belongs to.
        citation: Public research this payload is drawn from. Required.
        canary: The token the payload asks the target to emit.
        prompt: The user-turn text.
        documents: Retrieved documents to pass alongside the prompt. Non-empty
            for indirect injection, where the payload lives in the document
            rather than the user turn.
    """

    id: str
    attack_class: AttackClass
    citation: str
    canary: Canary
    prompt: str
    documents: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        """Enforce the corpus invariants at construction time.

        Raises:
            ValueError: The payload cites nothing, or its canary appears in its
                own input — which would make an echoing target register as a
                successful injection.
        """
        if not self.citation.strip():
            raise ValueError(f"probe {self.id!r} has no citation")
        if self.canary.value in self.rendered_input:
            raise ValueError(
                f"probe {self.id!r} leaks its canary {self.canary.value!r} into "
                "its own input; an echoing target would register as a success. "
                "Present the canary as fragments via `canary.instruction`."
            )

    @property
    def rendered_input(self) -> str:
        """Everything the target will see, normalised for canary comparison."""
        return normalize(self.prompt + "".join(self.documents))
