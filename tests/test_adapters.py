"""Loading and wrapping user applications as targets."""

import sys
from collections.abc import Sequence
from pathlib import Path

import pytest

from inject_probe.adapters import CallableTarget, load_target
from inject_probe.exceptions import ConfigError, TargetError
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


def test_a_file_target_can_import_its_siblings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Real entry points import their own modules; the file's directory must count."""
    monkeypatch.setattr(sys, "path", list(sys.path))
    (tmp_path / "sibling_helper.py").write_text('REPLY = "from sibling"\n')
    entry = tmp_path / "entry.py"
    entry.write_text(
        "import sibling_helper\n\ndef app(p):\n    return sibling_helper.REPLY\n"
    )
    assert load_target(f"{entry}:app").send("q").text == "from sibling"


def test_a_dotted_spec_resolves_from_the_working_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The console script does not put the working directory on `sys.path`."""
    monkeypatch.setattr(sys, "path", [p for p in sys.path if p not in ("", ".")])
    package = tmp_path / "cwd_package"
    package.mkdir()
    (package / "__init__.py").write_text('def app(p):\n    return "cwd"\n')
    monkeypatch.chdir(tmp_path)
    assert load_target("cwd_package:app").send("q").text == "cwd"


def test_an_exception_in_the_application_becomes_a_target_error() -> None:
    def app(prompt: str) -> str:
        raise RuntimeError("boom")

    with pytest.raises(TargetError, match="RuntimeError: boom"):
        CallableTarget.wrap(app).send("q")
