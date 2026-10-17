from __future__ import annotations

import os
from email.message import Message
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

import pytest

if TYPE_CHECKING:
    from importlib import metadata


def fake_distribution(
    name: str,
    version: str = "1.0",
    *,
    requires: list[str] | None = None,
    project_urls: list[tuple[str, str]] | None = None,
    homepage: str | None = None,
) -> metadata.Distribution:
    message = Message()
    message["Name"] = name
    message["Version"] = version
    if homepage:
        message["Home-page"] = homepage
    for label, url in project_urls or []:
        message["Project-URL"] = f"{label}, {url}"
    value = type(
        "FakeDistribution",
        (),
        {
            "metadata": message,
            "version": version,
            "requires": requires,
        },
    )()
    return cast("metadata.Distribution", cast("Any", value))


@pytest.fixture
def target_environment(tmp_path: Path) -> tuple[Path, Path]:
    """Create an environment with metadata but no pip-fund installation."""
    import json
    import subprocess
    import venv

    root = tmp_path / "target environment"
    venv.EnvBuilder(with_pip=False, symlinks=os.name != "nt").create(root)
    executable = root / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    result = subprocess.run(  # noqa: S603
        [
            str(executable),
            "-c",
            "import json,sysconfig; print(json.dumps(sysconfig.get_path('purelib')))",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    packages = Path(json.loads(result.stdout))
    for name, requires in [
        ("Alpha", "Requires-Dist: Bravo\n"),
        ("Bravo", ""),
        ("Unrelated", ""),
    ]:
        directory = packages / f"{name.lower()}-1.0.dist-info"
        directory.mkdir()
        (directory / "METADATA").write_text(
            f"Metadata-Version: 2.1\nName: {name}\nVersion: 1.0\n{requires}"
            f"Project-URL: Funding, https://example.com/{name.lower()}\n",
            encoding="utf-8",
        )
    return root, executable
