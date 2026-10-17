"""Command-line interface for project dependency funding audits."""

from __future__ import annotations

import argparse
import os
import sys
import webbrowser
from pathlib import Path
from typing import NoReturn

from pip_fund.discovery import FundingDiscovery
from pip_fund.environment import inspect_environment, select_interpreter
from pip_fund.models import Failure, Report
from pip_fund.project import (
    ProjectError,
    installed_environment,
    load_project_requirements,
    parse_package_requirements,
    resolve_installed_graph,
)
from pip_fund.reporting import format_json, format_markdown, format_text


def build_parser() -> argparse.ArgumentParser:
    """Create the command-line parser."""
    parser = argparse.ArgumentParser(
        prog="pip-fund",
        description=(
            "Find funding destinations for an environment or installed package and "
            "transitive dependencies."
        ),
    )
    parser.add_argument(
        "packages",
        nargs="*",
        help="Package requirements whose installed dependencies should be inspected.",
    )
    parser.add_argument(
        "--project",
        type=Path,
        default=None,
        help="Read dependencies from this project directory or pyproject.toml.",
    )
    parser.add_argument(
        "--python",
        help="Interpreter executable or path identifying the environment to inspect.",
    )
    parser.add_argument(
        "--extra",
        action="append",
        default=[],
        help="Include a project optional-dependency extra; may be repeated.",
    )
    parser.add_argument(
        "--group",
        action="append",
        default=[],
        help="Include a standardized dependency group; may be repeated.",
    )
    parser.add_argument(
        "--remote",
        action="store_true",
        help="Use the PyPI JSON API when installed metadata has no funding URL.",
    )
    parser.add_argument(
        "--github",
        action="store_true",
        help="Add repository FUNDING.yml destinations to installed metadata funding.",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json", "markdown"),
        default="text",
        help="Output format (default: text).",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit with status 1 when any lookup or graph issue occurs.",
    )
    parser.add_argument(
        "--open",
        action="store_true",
        dest="open_url",
        help="Open the sole discovered destination for one explicit package.",
    )
    return parser


def _validate_arguments(
    parser: argparse.ArgumentParser, arguments: argparse.Namespace
) -> None:
    if arguments.project is not None and arguments.packages:
        parser.error("--project cannot be combined with package arguments")
    if (arguments.extra or arguments.group) and arguments.project is None:
        parser.error("--extra and --group require --project")
    if arguments.open_url and len(arguments.packages) != 1:
        parser.error("--open requires exactly one explicit package")


def create_report(arguments: argparse.Namespace) -> Report:
    """Build a report from parsed CLI arguments."""
    graph_failures: tuple[Failure, ...] = ()
    requirements = None
    if arguments.project is not None:
        scope, requirements = load_project_requirements(
            arguments.project, extras=arguments.extra, groups=arguments.group
        )
    elif arguments.packages:
        requirements = parse_package_requirements(arguments.packages)
        scope = "packages " + ", ".join(arguments.packages)
    else:
        scope = "installed environment"
    interpreter = select_interpreter(python=arguments.python, project=arguments.project)
    environment = inspect_environment(interpreter)
    distributions = environment.distributions
    if requirements is None:
        packages = installed_environment(distributions=distributions)
    else:
        graph = resolve_installed_graph(
            requirements,
            distributions=distributions,
            marker_environment=environment.markers,
        )
        packages = graph.packages
        graph_failures = graph.failures

    discovery = FundingDiscovery(
        use_pypi=arguments.remote,
        use_github=arguments.github,
        github_token=os.environ.get("GITHUB_TOKEN"),
    )
    records, discovery_failures = discovery.discover(
        packages, distributions=distributions
    )
    return Report(
        scope=scope,
        interpreter=environment.interpreter,
        packages=packages,
        records=records,
        failures=(*graph_failures, *discovery_failures),
    )


def main(argv: list[str] | None = None) -> int:
    """Run the CLI and return its process status."""
    parser = build_parser()
    arguments = parser.parse_args(argv)
    _validate_arguments(parser, arguments)
    try:
        report = create_report(arguments)
    except ProjectError as error:
        parser.error(str(error))

    formatter = {
        "text": format_text,
        "json": format_json,
        "markdown": format_markdown,
    }[arguments.format]
    print(formatter(report))  # noqa: T201

    if arguments.open_url:
        if len(report.destinations) != 1:
            print(  # noqa: T201
                "pip-fund: --open requires one destination; "
                f"found {len(report.destinations)}",
                file=sys.stderr,
            )
            return 1
        webbrowser.open(report.destinations[0].url)
    return 1 if arguments.strict and report.failures else 0


def cli() -> NoReturn:
    """Console-script entry point."""
    raise SystemExit(main())
