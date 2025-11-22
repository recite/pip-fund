"""
Core implementation for the ``pip_fund`` command.

This module provides a command‑line interface for discovering funding
links associated with Python packages.  Funding information is
discovered by inspecting package metadata (``Project‑URL`` entries)
and, optionally, by querying the PyPI JSON API and GitHub’s
``.github/FUNDING.yml`` file when the optional ``github`` feature is
enabled.  Duplicate links are normalised and grouped across
packages so that each unique funding source is printed once with a
list of packages that declare it.

The default output is a simple human‑readable report, but JSON and
Markdown formats are available via command‑line switches.
"""

from __future__ import annotations

import argparse
import json
import os
import re
from collections import defaultdict
from collections.abc import Iterable, Mapping
from urllib.parse import urlparse, urlunparse

try:
    # ``importlib.metadata`` is in the standard library for Python 3.8+
    from importlib import metadata as importlib_metadata
except ImportError:  # pragma: no cover
    import importlib_metadata  # type: ignore

try:
    import requests  # type: ignore[import]
except ImportError:
    requests = None  # type: ignore[assignment]

# Optional GitHub dependencies.  These are only imported when the
# ``--github`` flag is provided *and* the extras have been installed.
try:
    import yaml  # type: ignore[import]
    from github import Github  # type: ignore[import]
except ImportError:
    Github = None  # type: ignore[assignment]
    yaml = None  # type: ignore[assignment]


# Normalised labels that count as “funding”.  See the Python Packaging
# User Guide’s “Well-known Project URLs” section for discussion of
# funding aliases.
FUNDING_ALIASES: set[str] = {
    "funding",
    "sponsor",
    "donate",
    "donation",
}


def normalise_label(label: str) -> str:
    """Normalise a Project‑URL label for comparison.

    Remove punctuation and whitespace and convert to lowercase.  This
    follows the rules described in the core metadata specification and
    PEP 753 for normalising project URL labels.

    Args:
        label: The label from a Project‑URL entry.

    Returns:
        The normalised label.
    """
    cleaned = re.sub(r"[^A-Za-z0-9]", "", label)
    return cleaned.lower()


def normalise_url(url: str) -> str:
    """Strip query parameters and fragments from a URL for grouping.

    Query strings and fragments often contain tracking parameters that
    should not affect whether two URLs refer to the same funding page.

    Args:
        url: The URL to normalise.

    Returns:
        The URL without ``?`` query parameters or ``#`` fragments.
    """
    try:
        parsed = urlparse(url)
        cleaned = parsed._replace(query="", fragment="")
        return urlunparse(cleaned)
    except Exception:
        return url


def extract_funding_urls_from_dist(
    dist: importlib_metadata.Distribution,
) -> list[tuple[str, str]]:
    """Extract funding URLs from a distribution's metadata.

    Args:
        dist: An ``importlib.metadata`` Distribution object.

    Returns:
        A list of ``(label, url)`` pairs representing funding‑related
        Project‑URL entries.  Labels are preserved as they appear in
        metadata; if an entry lacks a label, ``"Generic Link"`` is used.
    """
    funding_entries: list[tuple[str, str]] = []
    try:
        project_urls = dist.metadata.get_all("Project-URL", []) or []
    except Exception:
        project_urls = []
    for url_entry in project_urls:
        # Format: "Label, URL"
        if "," in url_entry:
            label, url = url_entry.split(",", 1)
            label = label.strip()
            url = url.strip()
            norm = normalise_label(label)
            if (
                norm in FUNDING_ALIASES
                or "fund" in norm
                or "sponsor" in norm
            ):
                funding_entries.append((label, url))
        else:
            url = url_entry.strip()
            if re.search(r"fund|sponsor", url, re.IGNORECASE):
                funding_entries.append(("Generic Link", url))
    return funding_entries


def query_pypi_project_urls(package_name: str) -> dict[str, str]:
    """Query the PyPI JSON API for a package's project URLs.

    When ``--remote`` is specified, this helper uses the public PyPI
    JSON API at ``https://pypi.org/pypi/<package>/json`` to retrieve
    the ``project_urls`` mapping.  The API returns a dictionary of
    well‑known URLs, including a possible "Funding" entry.

    Args:
        package_name: The name of the package on PyPI.

    Returns:
        A mapping of ``{label: url}``.  If the package does not exist
        or an error occurs, an empty dict is returned.  Requires
        ``requests`` to be installed.
    """
    if requests is None:
        return {}
    url = f"https://pypi.org/pypi/{package_name}/json"
    try:
        resp = requests.get(url, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            project_urls: Mapping[str, str] = (
                data.get("info", {}).get("project_urls", {}) or {}
            )
            return {
                str(k): str(v)
                for k, v in project_urls.items()
                if k and v
            }
    except Exception:
        pass
    return {}


def extract_github_repo_from_metadata(
    dist: importlib_metadata.Distribution,
) -> str | None:
    """Attempt to find a GitHub repository URL in a distribution's metadata.

    This helper inspects the ``Home-page`` field and ``Project-URL``
    entries for a link to a GitHub repository.  If found, it returns
    the repository in ``owner/repo`` form.  Otherwise it returns
    ``None``.

    Args:
        dist: A distribution to inspect.

    Returns:
        A string like ``"octocat/Hello-World"`` or ``None``.
    """
    # Check the Home-page field
    homepage = dist.metadata.get("Home-page")
    candidates: list[str] = []
    if homepage:
        candidates.append(homepage)
    # Also check Project-URL entries for labels like "Source" or
    # "Homepage" that might include the repository.  We don't use
    # funding labels here.
    try:
        project_urls = dist.metadata.get_all("Project-URL", []) or []
        for entry in project_urls:
            if "," in entry:
                label, url = entry.split(",", 1)
                label = label.strip().lower()
                url = url.strip()
                if label in {"source", "homepage", "code", "repository"}:
                    candidates.append(url)
            else:
                candidates.append(entry)
    except Exception:
        pass
    # Examine candidates for GitHub URLs
    for url in candidates:
        match = re.match(
            r"https?://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)",
            url,
        )
        if match:
            owner, repo = match.groups()
            return f"{owner}/{repo}"
    return None


def fetch_github_funding(repo_path: str, token: str | None) -> list[tuple[str, str]]:
    """Fetch funding links from a GitHub repository’s FUNDING.yml.

    This helper uses the GitHub API via the PyGithub library to fetch
    the contents of ``.github/FUNDING.yml`` for a given repository.
    If successful, it returns a list of ``(platform, url)`` pairs
    representing the configured funding sources.  If PyGithub or
    PyYAML is not installed, or the file does not exist, an empty
    list is returned.

    Args:
        repo_path: A string like ``"owner/repo"`` specifying the
            repository.
        token: Optional GitHub personal access token.  Without a
            token, unauthenticated requests may be subject to very
            strict rate limits.

    Returns:
        A list of ``(label, url)`` tuples.
    """
    if Github is None or yaml is None:
        return []
    try:
        gh = Github(login_or_token=token)
        repo = gh.get_repo(repo_path)
        contents = repo.get_contents(".github/FUNDING.yml")
        data = yaml.safe_load(contents.decoded_content)
        if not isinstance(data, dict):
            return []
        results: list[tuple[str, str]] = []
        for platform, entries in data.items():
            # Platform names correspond to GitHub sponsors ("github"),
            # Patreon ("patreon"), etc.  Entries may be strings or
            # lists of identifiers.  Construct a URL for each.
            if not entries:
                continue
            if isinstance(entries, str):
                entries = [entries]
            for entry in entries:
                # Map known platforms to URL patterns.  Unknown
                # platforms fall back to None and are skipped.
                if platform == "github":
                    url = f"https://github.com/sponsors/{entry}"
                    label = "GitHub Sponsors"
                elif platform == "patreon":
                    url = f"https://www.patreon.com/{entry}"
                    label = "Patreon"
                elif platform == "tidelift":
                    url = f"https://tidelift.com/funding/github/{entry}"
                    label = "Tidelift"
                elif platform == "custom":
                    url = entry
                    label = "Custom"
                else:
                    # Unknown platform type
                    continue
                results.append((label, url))
        return results
    except Exception:
        return []


def gather_funding_info(
    package_names: Iterable[str],
    use_remote: bool,
    use_github: bool,
    github_token: str | None,
) -> dict[str, list[tuple[str, str]]]:
    """Gather funding information for the given packages.

    Args:
        package_names: Names of packages to inspect.  If empty, all
            installed distributions are scanned.
        use_remote: Whether to query the PyPI JSON API for funding
            information about packages (useful when a package is not
            installed).  Requires ``requests``.
        use_github: Whether to attempt to discover funding links via
            GitHub’s ``FUNDING.yml`` file when no funding metadata is
            found locally or remotely.  Requires the ``github`` extra
            and a valid access token.
        github_token: Personal access token for the GitHub API.

    Returns:
        A mapping from package name to a list of ``(label, url)`` tuples.
    """
    results: dict[str, list[tuple[str, str]]] = defaultdict(list)
    if package_names:
        # Explicit list of packages
        for pkg in package_names:
            try:
                dist = importlib_metadata.distribution(pkg)
                entries = extract_funding_urls_from_dist(dist)
                results[pkg].extend(entries)
                # Optionally query PyPI for more links even if the
                # package is installed
                if use_remote:
                    pypi_urls = query_pypi_project_urls(pkg)
                    for lbl, url in pypi_urls.items():
                        norm = normalise_label(lbl)
                        if (
                            norm in FUNDING_ALIASES
                            or "fund" in norm
                            or "sponsor" in norm
                        ):
                            if (lbl, url) not in results[pkg]:
                                results[pkg].append((lbl, url))
            except importlib_metadata.PackageNotFoundError:
                # Not installed: try PyPI
                if use_remote:
                    pypi_urls = query_pypi_project_urls(pkg)
                    for lbl, url in pypi_urls.items():
                        norm = normalise_label(lbl)
                        if (
                            norm in FUNDING_ALIASES
                            or "fund" in norm
                            or "sponsor" in norm
                        ):
                            results[pkg].append((lbl, url))
            # If we still have no funding info and GitHub support is
            # enabled, attempt to fetch funding.yml
            if use_github and not results[pkg]:
                try:
                    dist = importlib_metadata.distribution(pkg)
                except importlib_metadata.PackageNotFoundError:
                    dist = None  # type: ignore
                repo_path = None
                if dist:
                    repo_path = extract_github_repo_from_metadata(dist)
                if not repo_path and use_remote:
                    # Try remote metadata for repository URL
                    # using the PyPI JSON API
                    pypi_urls = query_pypi_project_urls(pkg)
                    for _lbl, url in pypi_urls.items():
                        # look for GitHub repo in URL
                        match = re.match(
                            r"https?://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)",
                            url,
                        )
                        if match:
                            owner, repo = match.groups()
                            repo_path = f"{owner}/{repo}"
                            break
                if repo_path:
                    entries = fetch_github_funding(repo_path, github_token)
                    results[pkg].extend(entries)
    else:
        # Scan all installed distributions
        dists = list(importlib_metadata.distributions())
        for dist in dists:
            name = dist.metadata.get("Name", dist.metadata.get("Summary", "Unknown"))
            entries = extract_funding_urls_from_dist(dist)
            if entries:
                results[name].extend(entries)
            if use_remote and not entries:
                pypi_urls = query_pypi_project_urls(name)
                for lbl, url in pypi_urls.items():
                    norm = normalise_label(lbl)
                    if (
                        norm in FUNDING_ALIASES
                        or "fund" in norm
                        or "sponsor" in norm
                    ):
                        results[name].append((lbl, url))
            if use_github and not results[name]:
                repo_path = extract_github_repo_from_metadata(dist)
                if repo_path:
                    entries = fetch_github_funding(repo_path, github_token)
                    results[name].extend(entries)
    return results


def group_by_url(
    results: Mapping[str, list[tuple[str, str]]],
) -> Mapping[tuple[str, str], list[str]]:
    """Group funding results by URL.

    Normalises URLs before grouping so that links differing only in
    query parameters or fragments are treated as the same.

    Args:
        results: Mapping from package name to funding entries.

    Returns:
        A mapping where each key is a (label, canonical_url) tuple and
        the value is a list of packages that declare that funding
        entry.
    """
    grouped: dict[tuple[str, str], list[str]] = defaultdict(list)
    for pkg, entries in results.items():
        for lbl, url in entries:
            canon = normalise_url(url)
            grouped[(lbl, canon)].append(pkg)
    return grouped


def format_as_plain(results: Mapping[str, list[tuple[str, str]]]) -> str:
    """Format funding results as a human‑readable string.

    Funding entries are grouped by canonical URL.  Each unique entry
    appears once with the list of packages that declare it.  If no
    funding information is found, an explanatory message is returned.

    Args:
        results: Mapping from package to funding entries.

    Returns:
        A string representation of the report.
    """
    if not results:
        return (
            "No funding links found for any packages.\n"
            "This could mean:\n"
            "  - No packages declare funding links in their metadata.\n"
            "  - The packages use an older metadata format that doesn't support 'Project-URL'.\n"
            "  - The funding links are present but use a different, unrecognised label."
        )
    grouped = group_by_url(results)
    lines: list[str] = []
    lines.append("--- Funding Information Found ---")
    for (lbl, url), packages in sorted(grouped.items(), key=lambda kv: kv[0][1]):
        lines.append(f"{lbl}: {url}")
        lines.append("  Packages: " + ", ".join(sorted(packages)))
        lines.append("".join("-" for _ in range(30)))
    return "\n".join(lines)


def format_as_json(results: Mapping[str, list[tuple[str, str]]]) -> str:
    """Format funding results as a JSON string.

    Funding entries are grouped by canonical URL.  The JSON maps each
    unique link to an object containing the label, canonical URL and
    the list of packages that declare it.

    Args:
        results: Mapping from package to funding entries.

    Returns:
        A JSON string representation of the grouped report.
    """
    grouped = group_by_url(results)
    jsonable = {
        f"{lbl}|{url}": {
            "label": lbl,
            "url": url,
            "packages": sorted(packages),
        }
        for (lbl, url), packages in grouped.items()
    }
    return json.dumps(jsonable, indent=2)


def format_as_markdown(results: Mapping[str, list[tuple[str, str]]]) -> str:
    """Format funding results as a Markdown document.

    Funding entries are grouped by canonical URL.  Each entry is
    listed once with the packages that declare it.  Long lines are
    avoided to ensure readability.

    Args:
        results: Mapping from package to funding entries.

    Returns:
        A Markdown string representing the report.
    """
    if not results:
        return "No funding links found."
    grouped = group_by_url(results)
    lines: list[str] = []
    lines.append("# Funding Information\n")
    for (lbl, url), packages in sorted(grouped.items(), key=lambda kv: kv[0][1]):
        lines.append(f"* **{lbl}**: {url}")
        lines.append(f"  - Packages: {', '.join(sorted(packages))}\n")
    return "\n".join(lines)


def parse_arguments(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command‑line arguments.

    Args:
        argv: Optional list of arguments (for testing).  If omitted,
            defaults to ``sys.argv[1:]``.

    Returns:
        An ``argparse.Namespace`` containing parsed options.
    """
    parser = argparse.ArgumentParser(
        description=(
            "Enumerate funding links for Python packages by reading their metadata "
            "(and optionally PyPI project_urls and GitHub FUNDING.yml).\n"
            "Without arguments the script scans all installed distributions; "
            "otherwise supply package names to inspect them individually."
        )
    )
    parser.add_argument(
        "packages",
        nargs="*",
        help="Names of packages to inspect.  If omitted, all installed packages are scanned.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output the results as JSON instead of human‑readable text.",
    )
    parser.add_argument(
        "--markdown",
        action="store_true",
        help="Output the results as Markdown instead of human‑readable text.",
    )
    parser.add_argument(
        "--remote",
        action="store_true",
        help="Query the PyPI JSON API for packages (requires network and requests).",
    )
    parser.add_argument(
        "--github",
        action="store_true",
        help=(
            "Attempt to fetch funding links from a repository’s .github/FUNDING.yml via the GitHub API. "
            "Requires the github extra and a personal access token set via the GITHUB_TOKEN environment variable."
        ),
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    """Entry point for the ``pip_fund`` command.  Parses arguments and
    prints the formatted funding report.

    Args:
        argv: Optional list of arguments to parse (for testing).  If
            omitted, ``sys.argv[1:]`` is used.
    """
    args = parse_arguments(argv)
    token = os.environ.get("GITHUB_TOKEN") if args.github else None
    results = gather_funding_info(
        args.packages,
        use_remote=args.remote,
        use_github=args.github,
        github_token=token,
    )
    if args.json:
        print(format_as_json(results))
    elif args.markdown:
        print(format_as_markdown(results))
    else:
        print(format_as_plain(results))


if __name__ == "__main__":  # pragma: no cover
    main()
