"""Development automation sessions.

Single source of truth for lint, type-check and test commands. CI invokes these
sessions rather than duplicating the underlying tool invocations.
"""

import nox

nox.options.sessions = ["lint", "typecheck", "tests"]
nox.options.default_venv_backend = "uv"

# Lint and type-check run once on the supported floor, where version-sensitive
# type errors actually surface. Tests run across the full support matrix.
FLOOR_PYTHON = "3.12"
PYTHON_VERSIONS = ("3.12", "3.13", "3.14")
SOURCES = ("src", "tests", "examples", "noxfile.py")


@nox.session(python=FLOOR_PYTHON)
def lint(session: nox.Session) -> None:
    """Run the ruff linter and formatter check."""
    session.install("ruff")
    session.run("ruff", "check", *SOURCES)
    session.run("ruff", "format", "--check", *SOURCES)


@nox.session(python=FLOOR_PYTHON)
def format(session: nox.Session) -> None:
    """Apply ruff formatting and safe autofixes.

    Shadows the builtin deliberately: the session name is the CLI surface,
    `nox -s format`.
    """
    session.install("ruff")
    session.run("ruff", "check", "--fix", *SOURCES)
    session.run("ruff", "format", *SOURCES)


@nox.session(python=FLOOR_PYTHON)
def typecheck(session: nox.Session) -> None:
    """Run mypy in strict mode."""
    session.install("-e", ".[dev]")
    session.run("mypy")


@nox.session(python=PYTHON_VERSIONS)
def tests(session: nox.Session) -> None:
    """Run the pytest suite."""
    session.install("-e", ".[dev]")
    session.run("pytest", *session.posargs)
