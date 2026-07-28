"""Loading and wrapping user applications as targets."""

from collections.abc import Sequence
from pathlib import Path

import pytest

from inject_probe.adapters import CallableTarget, load_target
from inject_probe.exceptions import ConfigError
from inject_probe.target import TargetResponse

VULNERABLE_EXAMPLE = Path(__file__).parent.parent / "examples" / "vulnerable.py"


def test_loads_from_a_file_path_spec() -> None:
    target = load_target(f"{VULNERABLE_EXAMPLE}:app")
    assert target.send("hello").text


def test_loads_from_a_dotted_module_spec() -> None:
    target = load_target("dotted_target:app")
    assert target.send("hello").text == "dotted"


def test_passes_documents_when_the_callable_accepts_them() -> None:
    def app(prompt: str, documents: Sequence[str] = ()) -> str:
        return f"{prompt}|{len(documents)}"

    assert CallableTarget.wrap(app).send("q", documents=("a", "b")).text == "q|2"


def test_omits_documents_when_the_callable_does_not_accept_them() -> None:
    """A one-argument application is still worth testing for direct injection."""
    target = load_target("dotted_target:prompt_only")
    assert target.send("q", documents=("a", "b")).text == "prompt-only"


def test_accepts_a_callable_returning_a_target_response() -> None:
    def app(prompt: str) -> TargetResponse:
        return TargetResponse(text="typed", tool_calls=("search",))

    response = CallableTarget.wrap(app).send("q")
    assert response.text == "typed"
    assert response.tool_calls == ("search",)


def test_passes_through_an_object_that_already_implements_target() -> None:
    class Ready:
        def send(self, prompt: str, *, documents: Sequence[str] = ()) -> TargetResponse:
            return TargetResponse(text="native")

    assert CallableTarget.wrap(Ready().send).send("q").text == "native"


@pytest.mark.parametrize(
    "spec",
    ["no_colon", ":app", "dotted_target:", ""],
)
def test_rejects_a_malformed_spec(spec: str) -> None:
    with pytest.raises(ConfigError, match="malformed target spec"):
        load_target(spec)


def test_rejects_a_missing_attribute() -> None:
    with pytest.raises(ConfigError, match="has no attribute"):
        load_target("dotted_target:nope")


def test_rejects_a_non_callable_attribute() -> None:
    with pytest.raises(ConfigError, match="neither a Target"):
        load_target("dotted_target:NOT_CALLABLE")


def test_rejects_a_missing_file() -> None:
    with pytest.raises(ConfigError, match="no such file"):
        load_target("does/not/exist.py:app")
