# pip-fund

[![PyPI version](https://img.shields.io/pypi/v/pip-fund.svg)](https://pypi.org/project/pip-fund/)
[![Python versions](https://img.shields.io/pypi/pyversions/pip-fund.svg)](https://pypi.org/project/pip-fund/)
[![CI](https://github.com/recite/pip-fund/actions/workflows/ci.yml/badge.svg)](https://github.com/recite/pip-fund/actions/workflows/ci.yml)

Find funding links for installed Python packages. Run `pip-fund` to inspect a
Python environment, name packages to include their dependencies, or explicitly
select a project. Reports group shared funding destinations and show where each
link came from and which lookups were incomplete.

## Installation

```console
python -m pip install pip-fund
```

GitHub funding-file discovery needs the optional YAML parser:

```console
python -m pip install "pip-fund[github]"
```

## Choose what to inspect

Scan the active environment from any directory:

```console
pip-fund
```

The command uses an activated virtual environment or Conda environment when
available, otherwise the Python interpreter running pip-fund. It does not read a
project merely because the current directory contains `pyproject.toml`.

Select an interpreter explicitly:

```console
pip-fund --python /path/to/environment/bin/python
```

On Windows, a virtual environment's interpreter is usually
`C:\path\to\environment\Scripts\python.exe`. The target environment does not
need pip-fund installed. Every report identifies the interpreter inspected.

Inspect named packages and their installed dependencies:

```console
pip-fund requests "httpx[http2]"
pip-fund requests --python /path/to/environment/bin/python
```

Inspect the dependencies declared by a project:

```console
pip-fund --project /path/to/project
pip-fund --project /path/to/project --extra server --group test
pip-fund --project /path/to/project --python /path/to/environment/bin/python
```

Project mode reads the project's `pyproject.toml` and uses its `.venv`. If that
environment is missing, create it or supply `--python`; pip-fund will not silently
substitute another environment. `--extra` and `--group` require `--project`.

### Using pipx or uvx

Tools installed with pipx or uv have their own environments. Activate the
environment you want to inspect or provide a target explicitly:

```console
pipx install pip-fund
pip-fund --python /path/to/environment/bin/python
uvx --from pip-fund pip-fund --python /path/to/environment/bin/python
```

The `--python` after `pip-fund` selects the environment to inspect. A `--python`
option passed to uvx itself selects the interpreter that runs the tool.
Without activation or an explicit target, recognized pipx and uv tool
environments produce an error with instructions for selecting a target.

## Find additional funding links

Installed metadata is read locally. Network lookups are opt-in:

```console
pip-fund --remote --github
```

`--remote` queries PyPI when funding metadata is absent or a repository URL is
needed for GitHub discovery. `--github` adds links from a discovered repository's
`.github/FUNDING.yml`, even when installed metadata already supplies funding
links. Public repositories work without authentication; set `GITHUB_TOKEN` to
increase the API rate limit or access repositories visible to that token.

## Reports

```console
pip-fund --format json
pip-fund --format markdown
pip-fund --strict
pip-fund requests --remote --github --open
```

`--strict` exits with status 1 when missing dependencies, incompatible versions,
or lookup errors make the report incomplete. Invalid arguments or an unavailable
target interpreter exit with status 2. A package without a funding declaration
is not an error.

`--open` requires one explicit package and exactly one funding destination
across that package and its dependencies. It opens that destination in a browser.

For example, a project report might contain:

```text
Scanned 2 dependencies from project example.
2 packages advertise funding through 1 destinations.
Python: /path/to/project/.venv/bin/python

https://example.com/support
  Direct: Alpha
  Transitive: Bravo
  Labels: Funding
  Sources: metadata
```

Environment-wide reports list packages without assigning direct or indirect
relationships. JSON uses schema version 1 and includes the target interpreter,
summary counts, destinations, package versions, discovery sources, and issues.
Dependency depth and parent relationships are included for graph scans;
`direct` and `depth` are `null` for environment-wide scans.

## Discovery rules and limits

Funding labels are normalized using the PyPA Project-URL rules. The recognized
labels are `Funding`, `Sponsor`, `Donate`, and `Donation`. Links must use HTTP or
HTTPS. Grouping preserves URL fragments and meaningful query parameters while
removing five tracking parameters: `utm_campaign`, `utm_content`, `utm_medium`,
`utm_source`, and `utm_term`.

The dependency graph describes installed packages. pip-fund does not install
packages, resolve a lockfile, or measure which dependencies an application
actually uses. Python and platform conditions are evaluated for the selected
interpreter. Project mode supports standard `[project]` dependencies, optional
dependencies, and Dependency Groups. For dynamic dependencies or tool-specific
project formats, supply package requirements explicitly.

Funding declarations can be incomplete. An absent link does not establish that
a package is adequately funded or that its maintainers decline support.

## Changes from 0.1

Named-package scans now include installed dependencies. Use `--format json` or
`--format markdown` in place of `--json` or `--markdown`; the JSON structure and
Python API have changed. The default remains an environment scan.

## Development

Documentation tooling requires Python 3.12 or newer; the package supports Python
3.11 and newer.

```console
uv sync --all-groups --all-extras
make ci
```

## License

MIT
