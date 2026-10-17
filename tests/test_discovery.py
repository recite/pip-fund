from __future__ import annotations

import base64
import json
from typing import Any, cast

import pytest
import requests

from pip_fund.discovery import (
    FundingDiscovery,
    canonicalise_url,
    funding_urls_from_distribution,
    github_repository_from_distribution,
    normalise_label,
)
from pip_fund.models import Package
from tests.conftest import fake_distribution


class FakeResponse:
    def __init__(self, status_code: int, payload: Any) -> None:
        self.status_code = status_code
        self.payload = payload

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise requests.HTTPError(f"status {self.status_code}")

    def json(self) -> Any:
        return self.payload


class FakeSession:
    def __init__(self, responses: list[FakeResponse]) -> None:
        self.responses = responses
        self.urls: list[str] = []

    def get(self, url: str, **_: Any) -> FakeResponse:
        self.urls.append(url)
        return self.responses.pop(0)


def package(name: str = "demo", version: str | None = "1.0") -> Package:
    return Package(name=name, version=version, direct=True, depth=0)


def session(value: FakeSession) -> requests.Session:
    return cast("requests.Session", cast("Any", value))


def test_pep_753_normalisation_is_exact() -> None:
    assert normalise_label(" FUND-ing! ") == "funding"
    assert normalise_label("fund—ing") == "fund—ing"


def test_exact_aliases_avoid_refund_false_positive() -> None:
    distribution = fake_distribution(
        "demo",
        project_urls=[
            ("Refund Policy", "https://example.com/refund"),
            ("Sponsor", "https://example.com/support"),
        ],
    )

    assert funding_urls_from_distribution(distribution) == [
        ("Sponsor", "https://example.com/support")
    ]


def test_canonical_url_preserves_semantics_and_removes_tracking() -> None:
    alice = canonicalise_url(
        "HTTPS://PAY.EXAMPLE:443/?recipient=alice&utm_source=pypi#monthly"
    )
    bob = canonicalise_url("https://pay.example/?recipient=bob#monthly")

    assert alice == "https://pay.example/?recipient=alice#monthly"
    assert bob == "https://pay.example/?recipient=bob#monthly"
    assert alice != bob


@pytest.mark.parametrize("url", ["javascript:alert(1)", "https:///missing-host"])
def test_rejects_unsafe_or_invalid_urls(url: str) -> None:
    with pytest.raises(ValueError, match="funding URL"):
        canonicalise_url(url)


def test_rejects_urls_with_credentials() -> None:
    with pytest.raises(ValueError, match="credentials"):
        canonicalise_url("https://user:secret@example.com/pay")


def test_repository_detection_uses_well_known_labels_and_strips_dot_git() -> None:
    distribution = fake_distribution(
        "demo",
        project_urls=[("Source Code", "https://github.com/acme/demo.git")],
    )

    assert github_repository_from_distribution(distribution) == "acme/demo"


def test_repository_detection_falls_back_to_a_github_code_url() -> None:
    distribution = fake_distribution(
        "demo",
        project_urls=[
            ("Funding", "https://github.com/sponsors/alice"),
            ("Code", "https://github.com/acme/demo/issues"),
        ],
    )

    assert github_repository_from_distribution(distribution) == "acme/demo"


def test_groups_local_metadata_records_without_network() -> None:
    first = fake_distribution(
        "first", project_urls=[("Funding", "https://example.com/pay?utm_source=one")]
    )
    second = fake_distribution(
        "second", project_urls=[("Sponsor", "https://example.com/pay")]
    )
    discovery = FundingDiscovery()

    records, failures = discovery.discover(
        [package("first"), package("second")], distributions=[first, second]
    )

    assert len(records) == 2
    assert {record.canonical_url for record in records} == {"https://example.com/pay"}
    assert not failures


def test_invalid_local_funding_url_is_an_explicit_issue() -> None:
    distribution = fake_distribution(
        "demo", project_urls=[("Funding", "mailto:maintainer@example.com")]
    )

    records, failures = FundingDiscovery().discover(
        [package()], distributions=[distribution]
    )

    assert not records
    assert len(failures) == 1
    assert failures[0].source == "metadata"


def test_github_lookup_does_not_implicitly_query_pypi() -> None:
    fake_session = FakeSession([])
    discovery = FundingDiscovery(use_github=True, session=session(fake_session))

    records, failures = discovery.discover([package()], distributions=[])

    assert not records
    assert not failures
    assert not fake_session.urls


def test_pypi_is_an_explicit_fallback() -> None:
    fake_session = FakeSession(
        [
            FakeResponse(
                200,
                {
                    "info": {
                        "project_urls": {
                            "Funding": "https://example.com/fund",
                            "Source": "https://github.com/acme/demo",
                        }
                    }
                },
            )
        ]
    )
    discovery = FundingDiscovery(use_pypi=True, session=session(fake_session))

    records, failures = discovery.discover([package()], distributions=[])

    assert [(record.source, record.url) for record in records] == [
        ("pypi", "https://example.com/fund")
    ]
    assert not failures
    assert fake_session.urls == ["https://pypi.org/pypi/demo/1.0/json"]


def test_pypi_failure_is_reported() -> None:
    discovery = FundingDiscovery(
        use_pypi=True,
        session=session(FakeSession([FakeResponse(503, {})])),
    )

    records, failures = discovery.discover([package()], distributions=[])

    assert not records
    assert len(failures) == 1
    assert "PyPI lookup failed" in failures[0].message


def test_pypi_rejects_malformed_project_urls() -> None:
    discovery = FundingDiscovery(
        use_pypi=True,
        session=session(
            FakeSession([FakeResponse(200, {"info": {"project_urls": []}})])
        ),
    )

    records, failures = discovery.discover([package()], distributions=[])

    assert not records
    assert "not an object" in failures[0].message


def test_github_supports_all_documented_platforms() -> None:
    funding = {
        "community_bridge": "linux",
        "github": ["alice", "bob"],
        "issuehunt": "alice/demo",
        "ko_fi": "alice",
        "liberapay": "alice",
        "open_collective": "demo",
        "patreon": "alice",
        "tidelift": "pypi/demo",
        "polar": "alice",
        "buy_me_a_coffee": "alice",
        "thanks_dev": "u/gh/alice",
        "custom": ["https://example.com/pay"],
    }
    encoded = base64.b64encode(json.dumps(funding).encode()).decode()
    fake_session = FakeSession([FakeResponse(200, {"content": encoded})])
    distribution = fake_distribution(
        "demo", project_urls=[("GitHub", "https://github.com/acme/demo")]
    )
    discovery = FundingDiscovery(
        use_github=True,
        session=session(fake_session),
        github_token="test-token",  # noqa: S106
    )

    records, failures = discovery.discover([package()], distributions=[distribution])

    assert len(records) == 13
    assert not failures
    assert {record.label for record in records} >= {
        "GitHub Sponsors",
        "Open Collective",
        "thanks.dev",
        "Custom",
    }
    urls = {record.url for record in records}
    assert "https://tidelift.com/subscription/pkg/pypi-demo" in urls
    assert "https://crowdfunding.lfx.linuxfoundation.org/projects/linux" in urls


def test_github_enriches_existing_metadata_funding() -> None:
    encoded = base64.b64encode(b"github: alice\n").decode()
    funding = f"{encoded[:4]}\n{encoded[4:]}"
    fake_session = FakeSession([FakeResponse(200, {"content": funding})])
    distribution = fake_distribution(
        "demo",
        project_urls=[
            ("Funding", "https://example.com/pay"),
            ("Source", "https://github.com/acme/demo"),
        ],
    )

    records, failures = FundingDiscovery(
        use_github=True, session=session(fake_session)
    ).discover([package()], distributions=[distribution])

    assert {record.source for record in records} == {"metadata", "github"}
    assert not failures


def test_github_404_means_no_funding_file() -> None:
    fake_session = FakeSession([FakeResponse(404, {})])
    distribution = fake_distribution(
        "demo", project_urls=[("Source", "https://github.com/acme/demo")]
    )

    records, failures = FundingDiscovery(
        use_github=True, session=session(fake_session)
    ).discover([package()], distributions=[distribution])

    assert not records
    assert not failures


def test_github_reports_malformed_and_unsupported_entries() -> None:
    funding = {
        "custom": ["https://example.com/pay", 3],
        "github": ["alice", 4, ""],
        "unknown": "value",
    }
    encoded = base64.b64encode(json.dumps(funding).encode()).decode()
    fake_session = FakeSession([FakeResponse(200, {"content": encoded})])
    distribution = fake_distribution(
        "demo", project_urls=[("Source", "https://github.com/acme/demo")]
    )

    records, failures = FundingDiscovery(
        use_github=True, session=session(fake_session)
    ).discover([package()], distributions=[distribution])

    assert {record.label for record in records} == {"Custom", "GitHub Sponsors"}
    assert len(failures) == 4
    assert any("unsupported" in failure.message for failure in failures)


def test_github_normalises_a_schemeless_custom_link() -> None:
    funding = base64.b64encode(b"custom: example.com/pay\n").decode()
    fake_session = FakeSession([FakeResponse(200, {"content": funding})])
    distribution = fake_distribution(
        "demo", project_urls=[("Source", "https://github.com/acme/demo")]
    )

    records, failures = FundingDiscovery(
        use_github=True, session=session(fake_session)
    ).discover([package()], distributions=[distribution])

    assert [record.url for record in records] == ["https://example.com/pay"]
    assert not failures


def test_github_reports_invalid_api_content() -> None:
    fake_session = FakeSession([FakeResponse(200, {"content": "not base64"})])
    distribution = fake_distribution(
        "demo", project_urls=[("Source", "https://github.com/acme/demo")]
    )

    records, failures = FundingDiscovery(
        use_github=True, session=session(fake_session)
    ).discover([package()], distributions=[distribution])

    assert not records
    assert "GitHub lookup failed" in failures[0].message


@pytest.mark.parametrize("port", ["", ":8443", ":0"])
def test_canonical_url_preserves_ipv6_authority(port: str) -> None:
    url = f"https://[2001:db8::1]{port}/donate"
    assert canonicalise_url(url) == url


def test_github_keeps_valid_custom_links_after_malformed_url() -> None:
    funding = {"custom": ["https://[broken", "https://example.com/pay"]}
    encoded = base64.b64encode(json.dumps(funding).encode()).decode()
    fake_session = FakeSession([FakeResponse(200, {"content": encoded})])
    distribution = fake_distribution(
        "demo", project_urls=[("Source", "https://github.com/acme/demo")]
    )

    records, failures = FundingDiscovery(
        use_github=True, session=session(fake_session)
    ).discover([package()], distributions=[distribution])

    assert [record.url for record in records] == ["https://example.com/pay"]
    assert len(failures) == 1
    assert failures[0].source == "github"
    assert "Invalid IPv6 URL" in failures[0].message
