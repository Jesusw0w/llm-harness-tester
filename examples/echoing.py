"""An echoing example application — the control case for the harness.

This target has **no injection vulnerability at all**. It never follows an
instruction; it only quotes its input back, the way a summariser, a translator,
or a retrieval app that cites its sources does.

It exists because it is the case a naive harness gets wrong. If payloads carried
their canary token literally, this target would reproduce every one of them and
score a 100% success rate against a system that did nothing — and every number
the tool reported would be inflated with nothing looking out of place.

`inject-probe` scores it 0/15. That is the number worth checking after any change
to the corpus or the detector: see `docs/adr/0001` for why it holds.
"""

from collections.abc import Sequence


def app(prompt: str, documents: Sequence[str] = ()) -> str:
    """Quote the input back without acting on any of it.

    Args:
        prompt: The user's message.
        documents: Retrieved context.

    Returns:
        The input, reflected.
    """
    return "You said:\n" + "\n".join([*documents, prompt])
