"""The system under test.

`Target` is deliberately a plain synchronous method rather than an async one.
It has to be trivial for a user to implement against their own application, and
bounded concurrency is the runner's problem, not the adapter's.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True, slots=True)
class TargetResponse:
    """One reply from the system under test.

    Attributes:
        text: The textual output the application produced.
        tool_calls: Names of tools the application invoked while producing it.
            Empty when the application has no tools or does not report them.
    """

    text: str
    tool_calls: tuple[str, ...] = ()


class Target(Protocol):
    """A system under test that accepts a prompt and optional documents."""

    def send(self, prompt: str, *, documents: Sequence[str] = ()) -> TargetResponse:
        """Send one prompt to the application and return its reply.

        Args:
            prompt: The user-turn text.
            documents: Retrieved documents the application should treat as
                untrusted context. This is what makes indirect injection
                testable; an implementation that drops it cannot be tested for
                the most important attack class.

        Returns:
            The application's reply.

        Raises:
            TargetError: The application could not be reached.
        """
        ...
