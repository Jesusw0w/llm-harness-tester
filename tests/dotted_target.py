"""An importable module used to exercise the dotted-name form of a target spec."""

from collections.abc import Sequence


def app(prompt: str, documents: Sequence[str] = ()) -> str:
    """Return a fixed reply, ignoring its input.

    Args:
        prompt: Unused.
        documents: Unused.

    Returns:
        A constant.
    """
    return "dotted"


def prompt_only(prompt: str) -> str:
    """Accept a prompt and no documents, as a minimal application would.

    Args:
        prompt: The user-turn text.

    Returns:
        A constant.
    """
    return "prompt-only"


NOT_CALLABLE = 42
