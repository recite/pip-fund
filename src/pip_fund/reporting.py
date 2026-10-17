"""Render funding audit reports for humans and other tools."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping

    from pip_fund.models import Destination, FundingRecord, Package, Report


def _package_index(report: Report) -> Mapping[str, Package]:
    return {package.name.casefold(): package for package in report.packages}


def _destination_packages(
    destination: Destination, packages: Mapping[str, Package]
) -> tuple[list[str], list[str], list[str]]:
    names = sorted({record.package for record in destination.records}, key=str.casefold)
    direct = [name for name in names if packages[name.casefold()].direct]
    transitive = [name for name in names if packages[name.casefold()].direct is False]
    unclassified = [name for name in names if packages[name.casefold()].direct is None]
    return direct, transitive, unclassified


def format_text(report: Report) -> str:
    """Render a compact terminal report."""
    lines = [
        f"Scanned {len(report.packages)} dependencies from {report.scope}.",
        (
            f"Packages advertising funding: {report.funded_package_count}; "
            f"destinations: {len(report.destinations)}."
        ),
    ]
    if report.interpreter:
        lines.append(f"Python: {report.interpreter}")
    if report.failures:
        lines.append(f"Issues making this report incomplete: {len(report.failures)}.")

    packages = _package_index(report)
    for destination in report.destinations:
        direct, transitive, unclassified = _destination_packages(destination, packages)
        sources = sorted({record.source for record in destination.records})
        labels = sorted(
            {record.label for record in destination.records}, key=str.casefold
        )
        lines.extend(["", destination.url])
        if unclassified:
            lines.append(f"  Packages: {', '.join(unclassified)}")
        if direct:
            lines.append(f"  Direct: {', '.join(direct)}")
        if transitive:
            lines.append(f"  Transitive: {', '.join(transitive)}")
        lines.append(f"  Labels: {', '.join(labels)}")
        lines.append(f"  Sources: {', '.join(sources)}")

    if report.failures:
        lines.extend(["", "Issues:"])
        for failure in report.failures:
            subject = failure.package or report.scope
            lines.append(f"  - {subject} [{failure.source}]: {failure.message}")
    return "\n".join(lines)


def format_markdown(report: Report) -> str:
    """Render a Markdown funding report."""
    lines = [
        "# Dependency funding report",
        "",
        f"Scope: {report.scope}",
        "",
        (
            f"Scanned {len(report.packages)} dependencies; "
            f"Packages advertising funding: {report.funded_package_count}; "
            f"destinations: {len(report.destinations)}."
        ),
    ]
    if report.interpreter:
        lines.extend(["", f"Python: `{report.interpreter}`"])
    packages = _package_index(report)
    for destination in report.destinations:
        direct, transitive, unclassified = _destination_packages(destination, packages)
        sources = sorted({record.source for record in destination.records})
        lines.extend(["", f"## {destination.url}", ""])
        if unclassified:
            lines.append(f"- Packages: {', '.join(unclassified)}")
        if direct:
            lines.append(f"- Direct dependencies: {', '.join(direct)}")
        if transitive:
            lines.append(f"- Transitive dependencies: {', '.join(transitive)}")
        lines.append(f"- Sources: {', '.join(sources)}")

    if report.failures:
        lines.extend(["", "## Incomplete lookups", ""])
        for failure in report.failures:
            subject = failure.package or report.scope
            lines.append(f"- {subject} ({failure.source}): {failure.message}")
    return "\n".join(lines)


def format_json(report: Report) -> str:
    """Render the stable version 1 JSON schema."""
    packages = _package_index(report)
    destinations = []
    for destination in report.destinations:
        records_by_package: dict[str, list[FundingRecord]] = {}
        for record in destination.records:
            records_by_package.setdefault(record.package, []).append(record)
        destination_packages = []
        for name, records in sorted(
            records_by_package.items(), key=lambda item: item[0].casefold()
        ):
            package = packages[name.casefold()]
            destination_packages.append(
                {
                    "name": package.name,
                    "version": package.version,
                    "direct": package.direct,
                    "depth": package.depth,
                    "parents": list(package.parents),
                    "labels": sorted(
                        {record.label for record in records}, key=str.casefold
                    ),
                    "sources": sorted({record.source for record in records}),
                    "declared_urls": sorted({record.url for record in records}),
                }
            )
        destinations.append({"url": destination.url, "packages": destination_packages})

    payload = {
        "schema_version": 1,
        "scope": report.scope,
        "interpreter": report.interpreter,
        "summary": {
            "packages_scanned": len(report.packages),
            "packages_with_funding": report.funded_package_count,
            "destinations": len(report.destinations),
            "issues": len(report.failures),
        },
        "destinations": destinations,
        "issues": [
            {
                "package": failure.package,
                "source": failure.source,
                "message": failure.message,
            }
            for failure in report.failures
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=False)
