"""HTTP adapters, driven against a mock transport — no network in unit tests."""

import json
from collections.abc import Callable
from dataclasses import replace
from typing import Any

import httpx
import pytest

from inject_probe.adapters import HTTPTarget, chat_completions, json_endpoint
from inject_probe.exceptions import TargetError

URL = "https://example.invalid/v1/endpoint"

Handler = Callable[[httpx.Request], httpx.Response]


def mocked(target: HTTPTarget, handler: Handler) -> HTTPTarget:
    """Swap a target's client for one backed by a mock transport.

    Args:
        target: A target built by one of the factories.
        handler: The mock request handler.

    Returns:
        The same target, wired to the mock.
    """
    target.close()
    return replace(target, client=httpx.Client(transport=httpx.MockTransport(handler)))


def replying(body: object) -> Handler:
    """Build a handler that always returns `body` as JSON with status 200."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=body)

    return handler


def recording(sink: dict[str, Any], body: object) -> Handler:
    """Build a handler that records the decoded request body into `sink`."""

    def handler(request: httpx.Request) -> httpx.Response:
        sink.update(json.loads(request.content))
        return httpx.Response(200, json=body)

    return handler


def test_posts_the_prompt_and_documents() -> None:
    seen: dict[str, Any] = {}
    target = mocked(json_endpoint(URL), recording(seen, {"output": "ok"}))
    assert target.send("q", documents=("d1", "d2")).text == "ok"
    assert seen["prompt"] == "q"
    assert seen["documents"] == ["d1", "d2"]


def test_honours_custom_field_names() -> None:
    seen: dict[str, Any] = {}
    target = mocked(
        json_endpoint(URL, prompt_field="question", documents_field="context"),
        recording(seen, {"output": "ok"}),
    )
    target.send("q", documents=("d",))
    assert seen == {"question": "q", "context": ["d"]}


def test_omits_documents_when_the_endpoint_has_no_slot() -> None:
    seen: dict[str, Any] = {}
    target = mocked(
        json_endpoint(URL, documents_field=None), recording(seen, {"output": "ok"})
    )
    target.send("q", documents=("d1",))
    assert "documents" not in seen


def test_reads_a_nested_response_field() -> None:
    target = mocked(
        json_endpoint(URL, response_field="data.reply"),
        replying({"data": {"reply": "nested"}}),
    )
    assert target.send("q").text == "nested"


def test_the_factory_configures_headers_and_timeout() -> None:
    """Checked on the factory's own client; `mocked` replaces it."""
    target = json_endpoint(URL, headers={"Authorization": "Bearer t"}, timeout=5.0)
    try:
        assert target.client.headers["Authorization"] == "Bearer t"
        assert target.client.timeout.read == 5.0
    finally:
        target.close()


def test_chat_completions_shape() -> None:
    seen: dict[str, Any] = {}
    target = mocked(
        chat_completions(URL, model="test-model"),
        recording(seen, {"choices": [{"message": {"content": "hello"}}]}),
    )
    assert target.send("q", documents=("doc",)).text == "hello"
    assert seen["model"] == "test-model"
    assert len(seen["messages"]) == 2
    assert "doc" in seen["messages"][0]["content"]
    assert seen["messages"][1]["content"] == "q"


def test_chat_completions_omits_the_context_message_without_documents() -> None:
    seen: dict[str, Any] = {}
    target = mocked(
        chat_completions(URL, model="m"),
        recording(seen, {"choices": [{"message": {"content": "hello"}}]}),
    )
    target.send("q")
    assert len(seen["messages"]) == 1


def test_a_non_2xx_status_is_a_target_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, json={})

    with pytest.raises(TargetError, match="HTTP 503"):
        mocked(json_endpoint(URL), handler).send("q")


def test_invalid_json_is_a_target_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"not json")

    with pytest.raises(TargetError, match="invalid JSON"):
        mocked(json_endpoint(URL), handler).send("q")


def test_a_missing_response_field_is_a_target_error() -> None:
    target = mocked(json_endpoint(URL), replying({"unexpected": "shape"}))
    with pytest.raises(TargetError, match="has no field"):
        target.send("q")


def test_a_non_string_response_field_is_a_target_error() -> None:
    target = mocked(json_endpoint(URL), replying({"output": {"nested": "object"}}))
    with pytest.raises(TargetError, match="not a string"):
        target.send("q")


def test_a_transport_failure_is_a_target_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    with pytest.raises(TargetError, match="could not be reached"):
        mocked(json_endpoint(URL), handler).send("q")


def test_a_transport_error_becomes_an_errored_probe_not_a_crash() -> None:
    """The runner must survive an endpoint that is entirely down."""
    from inject_probe.attacks import build_probes
    from inject_probe.detect import Outcome
    from inject_probe.runner import run

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    target = mocked(json_endpoint(URL), handler)
    outcomes = run(target, build_probes(seed=0), concurrency=2)
    assert outcomes
    assert all(o.finding.outcome is Outcome.ERROR for o in outcomes)


def test_closes_as_a_context_manager() -> None:
    target = mocked(json_endpoint(URL), replying({"output": "ok"}))
    with target:
        assert target.send("q").text == "ok"
    assert target.client.is_closed
