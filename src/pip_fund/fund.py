"""Public convenience API for :mod:`pip_fund`."""

from pip_fund.cli import cli, main
from pip_fund.discovery import (
    FundingDiscovery,
    canonicalise_url,
    funding_urls_from_distribution,
    normalise_label,
)
from pip_fund.models import Destination, Failure, FundingRecord, Package, Report
from pip_fund.project import (
    load_project_requirements,
    resolve_installed_graph,
)
from pip_fund.reporting import format_json, format_markdown, format_text

__all__ = [
    "Destination",
    "Failure",
    "FundingDiscovery",
    "FundingRecord",
    "Package",
    "Report",
    "canonicalise_url",
    "cli",
    "format_json",
    "format_markdown",
    "format_text",
    "funding_urls_from_distribution",
    "load_project_requirements",
    "main",
    "normalise_label",
    "resolve_installed_graph",
]


if __name__ == "__main__":  # pragma: no cover
    cli()
