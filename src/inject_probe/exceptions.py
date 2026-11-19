"""Exception hierarchy.

The split is load-bearing: the CLI maps `ConfigError` to a usage exit code, and
the runner turns `TargetError` into a probe-level `error` result. Neither is
retried here; connection retries belong to the HTTP transport.
"""


class InjectProbeError(Exception):
    """Base class for every error raised by this package."""


class ConfigError(InjectProbeError):
    """The run was misconfigured — a bad target spec, an unreadable file.

    Not retryable, and not a property of the system under test.
    """


class TargetError(InjectProbeError):
    """The system under test could not be reached, raised, or replied unusably.

    Never a verdict. A target that answers and simply refuses the injection
    is a successful probe with a `blocked` outcome, never this.
    """
