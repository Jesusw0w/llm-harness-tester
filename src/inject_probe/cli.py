"""Command line interface.

`argparse` from the standard library. The surface is three subcommands; a CLI
framework has not been earned.
"""

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from inject_probe import __version__
from inject_probe.adapters import chat_completions, json_endpoint, load_target
from inject_probe.attacks import build_probes
from inject_probe.baseline import compare, load_baseline, render_comparison
from inject_probe.constants import (
    DEFAULT_CONCURRENCY,
    DEFAULT_SEED,
    EXIT_OK,
    EXIT_REGRESSION,
    EXIT_USAGE,
)
from inject_probe.exceptions import ConfigError, InjectProbeError
from inject_probe.probe import AttackClass
from inject_probe.report import build_report, render_table, to_json
from inject_probe.runner import run
from inject_probe.target import Target


def _positive_int(raw: str) -> int:
    """Parse a strictly positive integer argument.

    Args:
        raw: The raw argument value.

    Returns:
        The parsed value.

    Raises:
        argparse.ArgumentTypeError: The value is not an integer of at least 1.
    """
    try:
        value = int(raw)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not an integer: {raw!r}") from None
    if value < 1:
        raise argparse.ArgumentTypeError(f"must be at least 1, got {value}")
    return value


def _build_parser() -> argparse.ArgumentParser:
    """Construct the argument parser.

    Returns:
        The parser, with every subcommand registered.
    """
    parser = argparse.ArgumentParser(
        prog="inject-probe",
        description=(
            "Adversarial test harness for prompt injection. "
            "For systems you own or are authorised to test."
        ),
    )
    parser.add_argument("--version", action="version", version=__version__)
    subcommands = parser.add_subparsers(dest="command", required=True)

    run_command = subcommands.add_parser(
        "run", help="Execute the corpus against a target."
    )
    selector = run_command.add_mutually_exclusive_group(required=True)
    selector.add_argument(
        "--target",
        metavar="SPEC",
        help="Python callable, e.g. examples/vulnerable.py:app or pkg.module:app",
    )
    selector.add_argument(
        "--target-url",
        metavar="URL",
        help="JSON endpoint to POST each probe to.",
    )
    selector.add_argument(
        "--target-chat",
        metavar="URL",
        help="OpenAI chat-completions-shaped endpoint.",
    )
    run_command.add_argument(
        "--model", help="Model identifier, required with --target-chat."
    )
    run_command.add_argument(
        "--prompt-field",
        default="prompt",
        help="Request field for the prompt, with --target-url. Default 'prompt'.",
    )
    run_command.add_argument(
        "--documents-field",
        default="documents",
        help=(
            "Request field for documents, with --target-url. Pass an empty "
            "string if the endpoint has no slot for them — but note that "
            "indirect injection then cannot be tested."
        ),
    )
    run_command.add_argument(
        "--response-field",
        default="output",
        help="Dotted path to the reply text, with --target-url. Default 'output'.",
    )
    run_command.add_argument(
        "--header",
        action="append",
        default=[],
        metavar="K:V",
        help="Extra request header. Repeatable.",
    )
    run_command.add_argument(
        "--attack-class",
        choices=[cls.value for cls in AttackClass],
        help="Restrict the run to one attack class.",
    )
    run_command.add_argument(
        "--seed",
        type=int,
        default=DEFAULT_SEED,
        help=f"Run seed; canaries derive from it. Default {DEFAULT_SEED}.",
    )
    run_command.add_argument(
        "--concurrency",
        type=_positive_int,
        default=DEFAULT_CONCURRENCY,
        help=f"Probes in flight at once. Default {DEFAULT_CONCURRENCY}.",
    )
    run_command.add_argument(
        "--json",
        type=Path,
        metavar="PATH",
        help="Write the JSON report here. Also the file to record as a baseline.",
    )
    run_command.add_argument(
        "--baseline",
        type=Path,
        metavar="PATH",
        help=(
            "Fail the run on regressions against this recorded report. "
            "Record one by running with --json."
        ),
    )
    run_command.add_argument(
        "--fail-on-new",
        action="store_true",
        help="Also fail when a probe absent from the baseline succeeded.",
    )
    run_command.add_argument(
        "--quiet", action="store_true", help="Suppress the table on stdout."
    )

    list_command = subcommands.add_parser(
        "list-probes", help="List the probes in the corpus."
    )
    list_command.add_argument(
        "--attack-class",
        choices=[cls.value for cls in AttackClass],
        help="Restrict the listing to one attack class.",
    )
    list_command.add_argument(
        "--seed", type=int, default=DEFAULT_SEED, help="Seed used to build the corpus."
    )

    return parser


def _parse_headers(raw: Sequence[str]) -> dict[str, str]:
    """Parse repeated ``K:V`` header arguments.

    Args:
        raw: The raw ``--header`` values.

    Returns:
        The parsed headers.

    Raises:
        ConfigError: A value is not in ``Key:Value`` form.
    """
    headers: dict[str, str] = {}
    for item in raw:
        key, separator, value = item.partition(":")
        if not separator or not key.strip():
            raise ConfigError(f"malformed header {item!r}; expected 'Key:Value'")
        headers[key.strip()] = value.strip()
    return headers


def _select_target(arguments: argparse.Namespace) -> tuple[Target, str]:
    """Build the target the run was pointed at.

    Args:
        arguments: Parsed arguments.

    Returns:
        The target, and the spec string recorded in the report.

    Raises:
        ConfigError: `--target-chat` was given without `--model`.
    """
    headers = _parse_headers(arguments.header)
    if arguments.target_url:
        return (
            json_endpoint(
                arguments.target_url,
                prompt_field=arguments.prompt_field,
                documents_field=arguments.documents_field or None,
                response_field=arguments.response_field,
                headers=headers,
            ),
            arguments.target_url,
        )
    if arguments.target_chat:
        if not arguments.model:
            raise ConfigError("--target-chat requires --model")
        return (
            chat_completions(
                arguments.target_chat, model=arguments.model, headers=headers
            ),
            arguments.target_chat,
        )
    return load_target(arguments.target), arguments.target


def _run(arguments: argparse.Namespace) -> int:
    """Execute the `run` subcommand.

    Args:
        arguments: Parsed arguments.

    Returns:
        The process exit code.
    """
    attack_class = (
        AttackClass(arguments.attack_class) if arguments.attack_class else None
    )
    # Read the baseline before anything runs: a bad path should not cost a full
    # run against a paid endpoint, and `--json` may be about to overwrite it.
    baseline = (
        load_baseline(arguments.baseline) if arguments.baseline is not None else None
    )
    target, spec = _select_target(arguments)
    try:
        probes = build_probes(seed=arguments.seed, attack_class=attack_class)
        outcomes = run(target, probes, concurrency=arguments.concurrency)
    finally:
        closer = getattr(target, "close", None)
        if callable(closer):
            closer()
    report = build_report(outcomes, seed=arguments.seed, target=spec)

    if not arguments.quiet:
        print(render_table(report))

    if arguments.json is not None:
        arguments.json.write_text(to_json(report), encoding="utf-8")

    # No absolute threshold: no real system scores zero, so failing on the
    # presence of successes would make the tool useless in CI. Regression
    # comparison against a recorded baseline is what gates a build.
    if baseline is None:
        return EXIT_OK

    comparison = compare(report, baseline, arguments.baseline)
    if not arguments.quiet:
        print(render_comparison(comparison, arguments.baseline))
    if comparison.failed(fail_on_new=arguments.fail_on_new):
        return EXIT_REGRESSION
    return EXIT_OK


def _list_probes(arguments: argparse.Namespace) -> int:
    """Execute the `list-probes` subcommand.

    Args:
        arguments: Parsed arguments.

    Returns:
        The process exit code.
    """
    attack_class = (
        AttackClass(arguments.attack_class) if arguments.attack_class else None
    )
    for probe in build_probes(seed=arguments.seed, attack_class=attack_class):
        summary = probe.citation.splitlines()[0] if probe.citation else ""
        print(f"{probe.id:<40} {probe.attack_class.value:<10} {summary}")
    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point.

    Args:
        argv: Command line arguments, defaulting to `sys.argv[1:]`.

    Returns:
        The process exit code: 0 clean, 1 regression against a baseline,
        2 usage error.
    """
    parser = _build_parser()
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "run":
            return _run(arguments)
        return _list_probes(arguments)
    except InjectProbeError as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_USAGE
