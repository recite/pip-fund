"""Discover funding declarations from package and repository metadata."""

from __future__ import annotations

import base64
import binascii
import re
import string
from importlib import metadata
from typing import TYPE_CHECKING
from urllib.parse import parse_qsl, quote, urlencode, urlparse, urlunparse

import requests
from packaging.utils import canonicalize_name

from pip_fund.models import Failure, FundingRecord, FundingSource, Package

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

try:
    import yaml
except ImportError:  # pragma: no cover - exercised in a clean installation test
    yaml = None  # type: ignore[assignment]

FUNDING_LABELS = frozenset({"funding", "sponsor", "donate", "donation"})
SOURCE_LABELS = frozenset({"source", "repository", "sourcecode", "github"})
TRACKING_PARAMETERS = frozenset(
    {
        "utm_campaign",
        "utm_content",
        "utm_medium",
        "utm_source",
        "utm_term",
    }
)

PLATFORM_URLS: Mapping[str, tuple[str, str]] = {
    "community_bridge": (
        "LFX Mentorship",
        "https://crowdfunding.lfx.linuxfoundation.org/projects/{value}",
    ),
    "github": ("GitHub Sponsors", "https://github.com/sponsors/{value}"),
    "issuehunt": ("IssueHunt", "https://issuehunt.io/r/{value}"),
    "ko_fi": ("Ko-fi", "https://ko-fi.com/{value}"),
    "liberapay": ("Liberapay", "https://liberapay.com/{value}"),
    "open_collective": ("Open Collective", "https://opencollective.com/{value}"),
    "patreon": ("Patreon", "https://www.patreon.com/{value}"),
    "tidelift": ("Tidelift", "https://tidelift.com/subscription/pkg/{value}"),
    "polar": ("Polar", "https://polar.sh/{value}"),
    "buy_me_a_coffee": (
        "Buy Me a Coffee",
        "https://www.buymeacoffee.com/{value}",
    ),
    "thanks_dev": ("thanks.dev", "https://thanks.dev/{value}"),
}


def normalise_label(label: str) -> str:
    """Normalize a Project-URL label exactly as specified by PEP 753."""
    removal_map = str.maketrans("", "", string.punctuation + string.whitespace)
    return label.translate(removal_map).lower()


def canonicalise_url(url: str) -> str:
    """Return a safe grouping key while preserving URL semantics."""
    parsed = urlparse(url.strip())
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ValueError("funding URL must use http or https and include a host")

    scheme = parsed.scheme.lower()
    host = parsed.hostname.lower()
    port = parsed.port
    if port and not (
        (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    ):
        host = f"{host}:{port}"
    if parsed.username or parsed.password:
        raise ValueError("funding URL must not contain credentials")

    query = urlencode(
        [
            (key, value)
            for key, value in parse_qsl(parsed.query, keep_blank_values=True)
            if key.lower() not in TRACKING_PARAMETERS
            and not key.lower().startswith("utm_")
        ],
        doseq=True,
    )
    path = parsed.path or "/"
    return urlunparse((scheme, host, path, parsed.params, query, parsed.fragment))


def _project_urls(distribution: metadata.Distribution) -> list[tuple[str, str]]:
    entries = distribution.metadata.get_all("Project-URL") or []
    parsed: list[tuple[str, str]] = []
    for entry in entries:
        if "," not in entry:
            continue
        label, url = entry.split(",", 1)
        parsed.append((label.strip(), url.strip()))
    return parsed


def funding_urls_from_distribution(
    distribution: metadata.Distribution,
) -> list[tuple[str, str]]:
    """Extract exact well-known funding Project-URL entries."""
    return [
        (label, url)
        for label, url in _project_urls(distribution)
        if normalise_label(label) in FUNDING_LABELS
    ]


def github_repository_from_urls(
    project_urls: Iterable[tuple[str, str]], homepage: str | None = None
) -> str | None:
    """Extract ``owner/repository`` from standardized project URLs."""
    project_url_list = list(project_urls)
    preferred = [
        url
        for label, url in project_url_list
        if normalise_label(label) in SOURCE_LABELS
    ]
    if homepage:
        preferred.append(homepage)
    fallback = [
        url
        for label, url in project_url_list
        if normalise_label(label) not in FUNDING_LABELS and url not in preferred
    ]
    candidates = [*preferred, *fallback]
    for candidate in candidates:
        parsed = urlparse(candidate)
        if parsed.scheme not in {"http", "https"}:
            continue
        if (parsed.hostname or "").lower() not in {"github.com", "www.github.com"}:
            continue
        parts = [part for part in parsed.path.split("/") if part]
        if len(parts) < 2:
            continue
        owner, repository = parts[:2]
        repository = re.sub(r"\.git$", "", repository, flags=re.IGNORECASE)
        if owner.casefold() in {
            "features",
            "marketplace",
            "orgs",
            "sponsors",
            "topics",
        }:
            continue
        if owner and repository:
            return f"{owner}/{repository}"
    return None


def github_repository_from_distribution(
    distribution: metadata.Distribution,
) -> str | None:
    """Extract a GitHub repository path from installed metadata."""
    return github_repository_from_urls(
        _project_urls(distribution), distribution.metadata.get("Home-page")
    )


def _records(
    package: str,
    entries: Iterable[tuple[str, str]],
    source: FundingSource,
) -> tuple[list[FundingRecord], list[Failure]]:
    records: list[FundingRecord] = []
    failures: list[Failure] = []
    for label, url in entries:
        try:
            canonical_url = canonicalise_url(url)
        except (ValueError, UnicodeError) as error:
            failures.append(
                Failure(
                    package=package,
                    source=source,
                    message=f"invalid funding URL {url!r}: {error}",
                )
            )
            continue
        records.append(
            FundingRecord(
                package=package,
                label=label,
                url=url,
                canonical_url=canonical_url,
                source=source,
            )
        )
    return records, failures


class FundingDiscovery:
    """Discover funding links with explicit network diagnostics."""

    def __init__(
        self,
        *,
        use_pypi: bool = False,
        use_github: bool = False,
        github_token: str | None = None,
        session: requests.Session | None = None,
        timeout: float = 10,
    ) -> None:
        """Configure local and optional remote discovery.

        Args:
            use_pypi: Query PyPI when local metadata is insufficient.
            use_github: Query repository ``FUNDING.yml`` files.
            github_token: Optional GitHub bearer token.
            session: Requests session, primarily for connection reuse and testing.
            timeout: Per-request timeout in seconds.
        """
        self.use_pypi = use_pypi
        self.use_github = use_github
        self.github_token = github_token
        self.session = session or requests.Session()
        self.timeout = timeout

    def discover(
        self,
        packages: Iterable[Package],
        *,
        distributions: Iterable[metadata.Distribution] | None = None,
    ) -> tuple[tuple[FundingRecord, ...], tuple[Failure, ...]]:
        """Discover funding records for each selected package."""
        selected = metadata.distributions() if distributions is None else distributions
        index = {
            str(canonicalize_name(distribution.metadata["Name"])): distribution
            for distribution in selected
            if distribution.metadata["Name"]
        }
        records: list[FundingRecord] = []
        failures: list[Failure] = []

        for package in packages:
            distribution = index.get(str(canonicalize_name(package.name)))
            local_entries: list[tuple[str, str]] = []
            repository: str | None = None
            if distribution is not None:
                try:
                    local_entries = funding_urls_from_distribution(distribution)
                    repository = github_repository_from_distribution(distribution)
                except (AttributeError, TypeError, ValueError) as error:
                    failures.append(
                        Failure(
                            package=package.name,
                            source="metadata",
                            message=f"cannot read installed metadata: {error}",
                        )
                    )
            package_records, package_failures = _records(
                package.name, local_entries, "metadata"
            )
            records.extend(package_records)
            failures.extend(package_failures)

            needs_pypi = not package_records or (self.use_github and repository is None)
            if self.use_pypi and needs_pypi:
                remote_urls, remote_repository, failure = self._query_pypi(package)
                if failure:
                    failures.append(failure)
                repository = repository or remote_repository
                package_records, package_failures = _records(
                    package.name, remote_urls, "pypi"
                )
                records.extend(package_records)
                failures.extend(package_failures)

            if self.use_github:
                if repository is None:
                    continue
                github_entries, github_failures = self._query_github(
                    package.name, repository
                )
                failures.extend(github_failures)
                package_records, package_failures = _records(
                    package.name, github_entries, "github"
                )
                records.extend(package_records)
                failures.extend(package_failures)

        deduplicated = {
            (
                record.package.casefold(),
                record.canonical_url,
                record.source,
                record.label.casefold(),
            ): record
            for record in records
        }
        return (
            tuple(
                sorted(
                    deduplicated.values(),
                    key=lambda record: (
                        record.canonical_url,
                        record.package.casefold(),
                        record.source,
                    ),
                )
            ),
            tuple(failures),
        )

    def _query_pypi(
        self, package: Package
    ) -> tuple[list[tuple[str, str]], str | None, Failure | None]:
        encoded_name = quote(package.name, safe="")
        version_path = f"/{quote(package.version, safe='')}" if package.version else ""
        url = f"https://pypi.org/pypi/{encoded_name}{version_path}/json"
        try:
            response = self.session.get(url, timeout=self.timeout)
            response.raise_for_status()
            payload = response.json()
            if not isinstance(payload, dict) or not isinstance(
                payload.get("info"), dict
            ):
                raise ValueError("response does not contain an info object")
            project_urls = payload["info"].get("project_urls")
            if project_urls is None:
                project_urls = {}
            if not isinstance(project_urls, dict):
                raise ValueError("info.project_urls is not an object")
            parsed_urls = [
                (str(label), str(value))
                for label, value in project_urls.items()
                if label and value
            ]
            funding = [
                (label, value)
                for label, value in parsed_urls
                if normalise_label(label) in FUNDING_LABELS
            ]
            repository = github_repository_from_urls(parsed_urls)
            return funding, repository, None
        except (requests.RequestException, ValueError, TypeError) as error:
            return (
                [],
                None,
                Failure(
                    package=package.name,
                    source="pypi",
                    message=f"PyPI lookup failed: {error}",
                ),
            )

    def _query_github(
        self, package: str, repository: str
    ) -> tuple[list[tuple[str, str]], list[Failure]]:
        if yaml is None:
            return [], [
                Failure(
                    package=package,
                    source="github",
                    message="GitHub discovery requires the 'github' extra",
                )
            ]
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2026-03-10",
        }
        if self.github_token:
            headers["Authorization"] = f"Bearer {self.github_token}"
        url = f"https://api.github.com/repos/{repository}/contents/.github/FUNDING.yml"
        try:
            response = self.session.get(url, headers=headers, timeout=self.timeout)
            if response.status_code == 404:
                return [], []
            response.raise_for_status()
            payload = response.json()
            if not isinstance(payload, dict) or not isinstance(
                payload.get("content"), str
            ):
                raise ValueError("GitHub response does not contain file content")
            encoded_content = "".join(payload["content"].split())
            raw_content = base64.b64decode(encoded_content, validate=True)
            parsed = yaml.safe_load(raw_content)
            if parsed is None:
                return [], []
            if not isinstance(parsed, dict):
                raise ValueError("FUNDING.yml must contain a mapping")
        except (
            requests.RequestException,
            ValueError,
            TypeError,
            UnicodeError,
            binascii.Error,
            yaml.YAMLError,
        ) as error:
            return [], [
                Failure(
                    package=package,
                    source="github",
                    message=f"GitHub lookup failed for {repository}: {error}",
                )
            ]

        entries: list[tuple[str, str]] = []
        failures: list[Failure] = []
        for platform, values in parsed.items():
            if not values:
                continue
            if platform == "custom":
                selected_values = values if isinstance(values, list) else [values]
                for value in selected_values:
                    if isinstance(value, str):
                        if not urlparse(value).scheme:
                            value = f"https://{value}"
                        entries.append(("Custom", value))
                    else:
                        failures.append(
                            Failure(
                                package=package,
                                source="github",
                                message="custom FUNDING.yml entries must be strings",
                            )
                        )
                continue
            if platform not in PLATFORM_URLS:
                failures.append(
                    Failure(
                        package=package,
                        source="github",
                        message=f"unsupported FUNDING.yml platform: {platform}",
                    )
                )
                continue
            selected_values = values if isinstance(values, list) else [values]
            label, template = PLATFORM_URLS[platform]
            for value in selected_values:
                if not isinstance(value, str):
                    failures.append(
                        Failure(
                            package=package,
                            source="github",
                            message=f"{platform} FUNDING.yml entries must be strings",
                        )
                    )
                    continue
                identifier = value.strip()
                if not identifier:
                    failures.append(
                        Failure(
                            package=package,
                            source="github",
                            message=f"{platform} FUNDING.yml entries must not be empty",
                        )
                    )
                    continue
                if platform == "tidelift":
                    identifier = identifier.replace("/", "-")
                entries.append(
                    (label, template.format(value=quote(identifier, safe="/:@")))
                )
        return entries, failures
