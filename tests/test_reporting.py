from __future__ import annotations

import json

from pip_fund.models import Failure, FundingRecord, Package, Report
from pip_fund.reporting import format_json, format_markdown, format_text


def example_report() -> Report:
    return Report(
        scope="project demo",
        packages=(
            Package("Alpha", "1", True, 0),
            Package("Bravo", "2", False, 1, ("Alpha",)),
        ),
        records=(
            FundingRecord(
                "Alpha",
                "Funding",
                "https://example.com/pay?utm_source=pypi",
                "https://example.com/pay",
                "metadata",
            ),
            FundingRecord(
                "Bravo",
                "Sponsor",
                "https://example.com/pay",
                "https://example.com/pay",
                "pypi",
            ),
        ),
        failures=(Failure("Missing", "graph", "package is not installed"),),
    )


def test_text_groups_by_url_across_labels() -> None:
    output = format_text(example_report())

    assert output.count("https://example.com/pay\n") == 1
    assert "Direct: Alpha" in output
    assert "Transitive: Bravo" in output
    assert "Issues making this report incomplete: 1" in output


def test_json_has_versioned_deterministic_schema() -> None:
    payload = json.loads(format_json(example_report()))

    assert payload["schema_version"] == 1
    assert payload["summary"] == {
        "packages_scanned": 2,
        "packages_with_funding": 2,
        "destinations": 1,
        "issues": 1,
    }
    assert payload["destinations"][0]["packages"][1]["parents"] == ["Alpha"]


def test_markdown_reports_scope_and_failures() -> None:
    output = format_markdown(example_report())

    assert "Scope: project demo" in output
    assert "## Incomplete lookups" in output


def test_environment_report_does_not_invent_dependency_relationships():
    report = Report(
        scope="installed environment",
        interpreter="/env/bin/python",
        packages=(Package("Alpha", "1", None, None),),
        records=(example_report().records[0],),
    )
    text = format_text(report)
    markdown = format_markdown(report)
    assert "Packages: Alpha" in text
    assert "Transitive:" not in text
    assert "Packages: Alpha" in markdown
    assert "/env/bin/python" in markdown
    payload = json.loads(format_json(report))
    assert payload["interpreter"] == "/env/bin/python"
    assert payload["destinations"][0]["packages"][0]["direct"] is None
