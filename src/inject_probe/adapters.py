"""Adapters that present a user's application as a `Target`.

Three of them, and the third is a preset rather than a class: a
chat-completions endpoint is an HTTP JSON endpoint with a fixed request shape and
a fixed place to find the reply, so `chat_completions` builds an `HTTPTarget`
rather than duplicating it.

No provider SDKs. `httpx` against a chat-completions-shaped endpoint covers
OpenAI-compatible servers — vLLM, Ollama, LM Studio, gateways — without adding a
dependency per vendor.
"""

import importlib
import importlib.util
import inspect
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType, TracebackType
from typing import Any

import httpx

from inject_probe.constants import DEFAULT_RETRIES, DEFAULT_TIMEOUT_SECONDS
from inject_probe.exceptions import ConfigError, TargetError
from inject_probe.target import Target, TargetResponse

TargetCallable = Callable[..., str | TargetResponse]
BodyBuilder = Callable[[str, Sequence[str]], dict[str, Any]]


@dataclass(frozen=True, slots=True)
class CallableTarget:
    """Presents a plain Python callable as a `Target`.

    The callable may accept just a prompt, or a prompt plus a ``documents``
    keyword. Which one it is gets decided once, at construction, by inspecting
    the signature — a one-argument application is still worth testing for direct
    injection even though it cannot be tested for indirect.

    It may return either a `TargetResponse` or a bare string.

    Attributes:
        fn: The application entry point.
        accepts_documents: Whether `fn` takes a ``documents`` parameter.
    """

    fn: TargetCallable
    accepts_documents: bool

    @classmethod
    def wrap(cls, fn: TargetCallable) -> "CallableTarget":
        """Build an adapter around a callable, inspecting its signature once.

        Args:
            fn: The application entry point.

        Returns:
            The adapter.

        Raises:
            ConfigError: The signature could not be inspected.
        """
        try:
            parameters = inspect.signature(fn).parameters
        except (TypeError, ValueError) as error:  # builtins, C callables
            raise ConfigError(f"cannot inspect target signature: {error}") from error
        return cls(fn=fn, accepts_documents="documents" in parameters)

    def send(self, prompt: str, *, documents: Sequence[str] = ()) -> TargetResponse:
        """Call the application and normalise whatever it returns.

        Args:
            prompt: The user-turn text.
            documents: Untrusted context to pass through, when the callable
                accepts it.

        Returns:
            The application's reply.
        """
        result = (
            self.fn(prompt, documents=documents)
            if self.accepts_documents
            else self.fn(prompt)
        )
        if isinstance(result, TargetResponse):
            return result
        return TargetResponse(text=result)


def _extract(payload: Any, pointer: Sequence[str | int]) -> str:  # noqa: ANN401
    """Walk a decoded JSON body to the field holding the reply text.

    Args:
        payload: The decoded response body.
        pointer: Keys and indices to follow, in order.

    Returns:
        The text at that location.

    Raises:
        TargetError: The path does not exist, or does not lead to a string. This
            is a transport-shaped failure rather than a probe result: the target
            answered, but not in the shape it was configured to answer in.
    """
    current: Any = payload
    for step in pointer:
        try:
            current = current[step]
        except (KeyError, IndexError, TypeError) as error:
            path = ".".join(str(part) for part in pointer)
            raise TargetError(
                f"response has no field {path!r} (failed at {step!r}): {error}"
            ) from error
    if not isinstance(current, str):
        path = ".".join(str(part) for part in pointer)
        raise TargetError(
            f"response field {path!r} is {type(current).__name__}, not a string"
        )
    return current


@dataclass(frozen=True, slots=True)
class HTTPTarget:
    """Presents an HTTP JSON endpoint as a `Target`.

    Retries are the transport's job, not the runner's: `httpx.HTTPTransport`
    retries connection failures only, before any response exists. Retrying after
    a reply would risk overwriting a real result with a second, different one.

    Attributes:
        url: The endpoint to POST to.
        build_body: Turns a prompt and documents into the request body.
        response_pointer: Path to the reply text within the response body.
        client: The HTTP client, owned by this target.
    """

    url: str
    build_body: BodyBuilder
    response_pointer: tuple[str | int, ...]
    client: httpx.Client = field(compare=False)

    def send(self, prompt: str, *, documents: Sequence[str] = ()) -> TargetResponse:
        """POST one probe to the endpoint and extract the reply.

        `tool_calls` is left empty: no v1 detector reads it, and guessing at
        every vendor's tool-call shape without a consumer would be speculation.

        Args:
            prompt: The user-turn text.
            documents: Untrusted context.

        Returns:
            The application's reply.

        Raises:
            TargetError: The endpoint could not be reached, returned a non-2xx
                status, returned invalid JSON, or answered in an unexpected
                shape.
        """
        try:
            body = self.build_body(prompt, documents)
            response = self.client.post(self.url, json=body)
            response.raise_for_status()
            payload = response.json()
        except httpx.HTTPStatusError as error:
            raise TargetError(
                f"{self.url} returned HTTP {error.response.status_code}"
            ) from error
        except httpx.HTTPError as error:
            raise TargetError(f"{self.url} could not be reached: {error}") from error
        except ValueError as error:
            raise TargetError(f"{self.url} returned invalid JSON: {error}") from error
        return TargetResponse(text=_extract(payload, self.response_pointer))

    def close(self) -> None:
        """Release the underlying connection pool."""
        self.client.close()

    def __enter__(self) -> "HTTPTarget":
        """Return self, so the target can be used as a context manager."""
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Close the client on exit."""
        self.close()


def _client(
    headers: Mapping[str, str] | None, timeout: float, retries: int
) -> httpx.Client:
    """Build an HTTP client that retries connection failures only.

    Args:
        headers: Extra headers to send with every request.
        timeout: Per-request timeout in seconds.
        retries: Connection-level retry attempts.

    Returns:
        The configured client.
    """
    return httpx.Client(
        headers=dict(headers or {}),
        timeout=timeout,
        transport=httpx.HTTPTransport(retries=retries),
    )


def json_endpoint(
    url: str,
    *,
    prompt_field: str = "prompt",
    documents_field: str | None = "documents",
    response_field: str = "output",
    headers: Mapping[str, str] | None = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    retries: int = DEFAULT_RETRIES,
) -> HTTPTarget:
    """Build a target for a plain JSON endpoint.

    Args:
        url: The endpoint to POST to.
        prompt_field: Request field to put the prompt in.
        documents_field: Request field to put documents in, or `None` if the
            endpoint has no slot for them. An endpoint without one cannot be
            tested for indirect injection.
        response_field: Dotted path to the reply text in the response body,
            e.g. ``output`` or ``data.reply``.
        headers: Extra headers, for authentication.
        timeout: Per-request timeout in seconds.
        retries: Connection-level retry attempts.

    Returns:
        The configured target.
    """

    def build_body(prompt: str, documents: Sequence[str]) -> dict[str, Any]:
        body: dict[str, Any] = {prompt_field: prompt}
        if documents_field is not None:
            body[documents_field] = list(documents)
        return body

    return HTTPTarget(
        url=url,
        build_body=build_body,
        response_pointer=tuple(response_field.split(".")),
        client=_client(headers, timeout, retries),
    )


def chat_completions(
    url: str,
    *,
    model: str,
    headers: Mapping[str, str] | None = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    retries: int = DEFAULT_RETRIES,
) -> HTTPTarget:
    """Build a target for an OpenAI chat-completions-shaped endpoint.

    A preset over `HTTPTarget`, not a separate adapter: the only differences are
    the request body and where the reply lives.

    Documents are sent as a separate user message labelled as retrieved context,
    which is the arrangement real retrieval-augmented applications use — and the
    arrangement indirect injection exploits.

    Args:
        url: The chat-completions endpoint.
        model: Model identifier to request.
        headers: Extra headers, for authentication.
        timeout: Per-request timeout in seconds.
        retries: Connection-level retry attempts.

    Returns:
        The configured target.
    """

    def build_body(prompt: str, documents: Sequence[str]) -> dict[str, Any]:
        messages: list[dict[str, str]] = []
        if documents:
            joined = "\n\n".join(documents)
            messages.append(
                {"role": "user", "content": f"Retrieved context:\n{joined}"}
            )
        messages.append({"role": "user", "content": prompt})
        return {"model": model, "messages": messages}

    return HTTPTarget(
        url=url,
        build_body=build_body,
        response_pointer=("choices", 0, "message", "content"),
        client=_client(headers, timeout, retries),
    )


def _load_module(reference: str) -> ModuleType:
    """Import a module from a filesystem path or a dotted name.

    Args:
        reference: Either ``path/to/file.py`` or ``package.module``.

    Returns:
        The imported module.

    Raises:
        ConfigError: The module could not be found or executed.
    """
    path = Path(reference)
    if path.suffix == ".py" or path.exists():
        if not path.is_file():
            raise ConfigError(f"no such file: {reference}")
        spec = importlib.util.spec_from_file_location(path.stem, path)
        if spec is None or spec.loader is None:
            raise ConfigError(f"cannot load a module from {reference}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    try:
        return importlib.import_module(reference)
    except ImportError as error:
        raise ConfigError(f"cannot import {reference!r}: {error}") from error


def load_target(spec: str) -> Target:
    """Load a target from a ``module:attribute`` spec.

    Accepts both forms::

        examples/vulnerable.py:app
        my_package.entrypoints:app

    The attribute may be an object implementing `Target`, or any callable, which
    is wrapped in a `CallableTarget`.

    Args:
        spec: The target specification.

    Returns:
        The loaded target.

    Raises:
        ConfigError: The spec is malformed, or the attribute is missing or is
            neither a `Target` nor callable.
    """
    reference, separator, attribute = spec.rpartition(":")
    if not separator or not reference or not attribute:
        raise ConfigError(
            f"malformed target spec {spec!r}; expected 'module:attribute', "
            "for example 'examples/vulnerable.py:app'"
        )

    module = _load_module(reference)
    try:
        loaded: Any = getattr(module, attribute)
    except AttributeError as error:
        raise ConfigError(f"{reference} has no attribute {attribute!r}") from error

    if hasattr(loaded, "send"):
        target: Target = loaded
        return target
    if callable(loaded):
        return CallableTarget.wrap(loaded)
    raise ConfigError(f"{spec} is neither a Target (no `send` method) nor callable")
