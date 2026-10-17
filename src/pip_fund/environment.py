"""Select and inspect the Python environment being audited."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from importlib import metadata
from pathlib import Path
from typing import TYPE_CHECKING, NoReturn

from packaging.markers import default_environment

from pip_fund.project import ProjectError

if TYPE_CHECKING:
    from collections.abc import Mapping


@dataclass(frozen=True)
class MetadataDistribution(metadata.Distribution):
    """Installed distribution metadata collected from another interpreter."""

    text: str

    def read_text(self, filename: str) -> str | None:
        """Return the collected metadata for a metadata filename."""
        return self.text if filename in {"METADATA", "PKG-INFO"} else None

    def locate_file(self, path: str | os.PathLike[str]) -> NoReturn:
        """Reject file lookup because snapshots contain metadata only."""
        raise NotImplementedError("metadata snapshots do not contain package files")


@dataclass(frozen=True)
class Environment:
    """Interpreter identity, marker values, and installed distributions."""

    interpreter: str
    markers: Mapping[str, str]
    distributions: tuple[metadata.Distribution, ...]


def _venv_python(root: Path) -> Path:
    executable = root / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    if os.name == "nt" and not executable.is_file():
        executable = root / "python.exe"
    if not executable.is_file():
        raise ProjectError(
            f"no Python interpreter found in {root}; create the environment "
            "or select an installed interpreter with --python /path/to/python"
        )
    return executable.absolute()


def _tool_environment(prefix: Path) -> bool:
    if any(
        (prefix / name).is_file() for name in ("pipx_metadata.json", "uv-receipt.toml")
    ):
        return True
    # uvx and ephemeral `uv run --with` environments live in the cache archive.
    return (
        bool(re.fullmatch(r"archive-v\d+", prefix.parent.name))
        and (prefix / "pyvenv.cfg").is_file()
    )


def select_interpreter(
    *, python: str | None = None, project: Path | None = None
) -> Path:
    """Select an explicit interpreter, project environment, or active environment."""
    if python is not None:
        selected = shutil.which(str(Path(python).expanduser()))
        if selected is None:
            raise ProjectError(
                f"cannot find interpreter {python!r}; use --python /path/to/python"
            )
        # Resolving the final symlink would turn a venv Python into its base Python.
        return Path(selected).absolute()
    if project is not None:
        root = project.parent if project.name == "pyproject.toml" else project
        return _venv_python(root / ".venv")
    active = os.environ.get("VIRTUAL_ENV") or os.environ.get("CONDA_PREFIX")
    if active:
        root = Path(active)
        if not _tool_environment(root.resolve()):
            return _venv_python(root)
    if _tool_environment(Path(sys.prefix).resolve()):
        raise ProjectError(
            "pip-fund is running in an isolated tool environment; activate the "
            "environment to inspect, use --python /path/to/python, or select "
            "a project with --project /path/to/project"
        )
    return Path(sys.executable).absolute()


def inspect_environment(interpreter: Path) -> Environment:
    """Read metadata in the selected interpreter without installing pip-fund there."""
    probe = Path(__file__).with_name("_probe.py")
    try:
        result = subprocess.run(  # noqa: S603
            [str(interpreter), "-E", str(probe)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ProjectError(
            f"cannot inspect interpreter {interpreter}: {error}"
        ) from error
    if result.returncode:
        raise ProjectError(
            f"cannot inspect interpreter {interpreter}: "
            f"{result.stderr.strip() or 'interpreter exited without metadata'}"
        )
    try:
        payload = json.loads(result.stdout)
        executable = payload["interpreter"]
        markers = payload["markers"]
        distributions = payload["distributions"]
        if not isinstance(executable, str) or not executable:
            raise ValueError("missing interpreter identity")
        if not isinstance(markers, dict) or not all(
            isinstance(key, str) and isinstance(value, str)
            for key, value in markers.items()
        ):
            raise ValueError("invalid marker environment")
        if not set(default_environment()) <= markers.keys():
            raise ValueError("incomplete marker environment")
        if not isinstance(distributions, list) or not all(
            isinstance(value, str) for value in distributions
        ):
            raise ValueError("invalid distribution metadata")
    except (ValueError, KeyError, TypeError) as error:
        raise ProjectError(f"invalid metadata from {interpreter}: {error}") from error
    return Environment(
        interpreter=executable,
        markers=markers,
        distributions=tuple(MetadataDistribution(value) for value in distributions),
    )
