from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from packaging.markers import default_environment

from pip_fund import environment
from pip_fund.environment import (
    inspect_environment,
    select_interpreter,
)
from pip_fund.project import (
    ProjectError,
    parse_package_requirements,
    resolve_installed_graph,
)
from tests.conftest import fake_distribution


def test_inspects_separate_environment_without_installing_tool(target_environment):
    _, executable = target_environment
    result = inspect_environment(executable)
    assert result.interpreter == str(executable)
    assert {d.metadata["Name"] for d in result.distributions} == {
        "Alpha",
        "Bravo",
        "Unrelated",
    }
    assert result.markers == default_environment()
    assert result.distributions[0].read_text("RECORD") is None
    with pytest.raises(NotImplementedError):
        result.distributions[0].locate_file("anything")


def test_explicit_python_preserves_venv_symlink(target_environment, monkeypatch):
    root, executable = target_environment
    monkeypatch.setenv("VIRTUAL_ENV", "/missing/environment")
    assert (
        select_interpreter(python=str(executable), project=Path("/missing/project"))
        == executable
    )
    assert select_interpreter(python=str(executable)).parent.parent == root


def test_selects_activated_environment(target_environment, monkeypatch):
    root, executable = target_environment
    monkeypatch.setenv("VIRTUAL_ENV", str(root))
    assert select_interpreter() == executable


def test_selects_conda_environment(target_environment, monkeypatch):
    root, executable = target_environment
    monkeypatch.delenv("VIRTUAL_ENV", raising=False)
    monkeypatch.setenv("CONDA_PREFIX", str(root))
    assert select_interpreter() == executable


def test_normal_install_uses_running_interpreter(tmp_path, monkeypatch):
    monkeypatch.delenv("VIRTUAL_ENV", raising=False)
    monkeypatch.delenv("CONDA_PREFIX", raising=False)
    monkeypatch.setattr(sys, "prefix", str(tmp_path))
    assert select_interpreter() == Path(sys.executable).absolute()


@pytest.mark.parametrize("receipt", ["pipx_metadata.json", "uv-receipt.toml", "cached"])
def test_isolated_tool_requires_target(tmp_path, monkeypatch, receipt):
    root = tmp_path / "archive-v0" / "environment" if receipt == "cached" else tmp_path
    root.mkdir(parents=True, exist_ok=True)
    (root / ("pyvenv.cfg" if receipt == "cached" else receipt)).touch()
    monkeypatch.delenv("VIRTUAL_ENV", raising=False)
    monkeypatch.delenv("CONDA_PREFIX", raising=False)
    monkeypatch.setattr(sys, "prefix", str(root))
    with pytest.raises(ProjectError, match="isolated tool environment"):
        select_interpreter()
    monkeypatch.setenv("VIRTUAL_ENV", str(root))
    with pytest.raises(ProjectError, match="isolated tool environment"):
        select_interpreter()


def test_activation_overrides_tool_environment(
    tmp_path, target_environment, monkeypatch
):
    root, executable = target_environment
    (tmp_path / "pipx_metadata.json").touch()
    monkeypatch.setattr(sys, "prefix", str(tmp_path))
    monkeypatch.setenv("VIRTUAL_ENV", str(root))
    assert select_interpreter() == executable


def test_missing_project_environment_does_not_fall_back(
    tmp_path, target_environment, monkeypatch
):
    monkeypatch.setenv("VIRTUAL_ENV", str(target_environment[0]))
    with pytest.raises(ProjectError, match="no Python interpreter"):
        select_interpreter(project=tmp_path)


def test_project_path_and_pyproject_select_same_environment(
    tmp_path, target_environment
):
    root, executable = target_environment
    project = tmp_path / "project"
    project.mkdir()
    (project / ".venv").symlink_to(root, target_is_directory=True)
    selected = select_interpreter(project=project)
    assert selected == project / ".venv" / executable.relative_to(root)
    assert select_interpreter(project=project / "pyproject.toml") == selected


def test_unknown_interpreter_is_actionable():
    with pytest.raises(ProjectError, match="cannot find interpreter"):
        select_interpreter(python="/no/such/python")


@pytest.mark.parametrize(
    "error", [OSError("permission denied"), subprocess.TimeoutExpired("python", 30)]
)
def test_probe_execution_errors_become_diagnostics(monkeypatch, error):
    def fail(*args, **kwargs):
        raise error

    monkeypatch.setattr(environment.subprocess, "run", fail)
    with pytest.raises(ProjectError, match="cannot inspect interpreter"):
        inspect_environment(Path("/target/python"))


@pytest.mark.parametrize(
    "payload",
    [
        "not json",
        "{}",
        '{"interpreter": null}',
        json.dumps(
            {"interpreter": "/target/python", "markers": {}, "distributions": []}
        ),
    ],
)
def test_invalid_probe_output_is_rejected(monkeypatch, payload):
    monkeypatch.setattr(
        environment.subprocess,
        "run",
        lambda *a, **kw: subprocess.CompletedProcess([], 0, payload, ""),
    )
    with pytest.raises(ProjectError, match="invalid metadata"):
        inspect_environment(Path("/target/python"))


def test_failed_interpreter_reports_stderr(monkeypatch):
    monkeypatch.setattr(
        environment.subprocess,
        "run",
        lambda *a, **kw: subprocess.CompletedProcess([], 1, "", "broken interpreter"),
    )
    with pytest.raises(ProjectError, match="broken interpreter"):
        inspect_environment(Path("/target/python"))


def test_dependency_conditions_use_target_python_and_platform():
    markers = dict(default_environment())
    markers.update(
        python_version="3.11", python_full_version="3.11.9", sys_platform="win32"
    )
    distributions = [
        fake_distribution(
            "Root",
            requires=[
                'OldPython; python_version < "3.12"',
                'Windows; sys_platform == "win32"',
                'NewPython; python_version >= "3.12"',
            ],
        ),
        fake_distribution("OldPython"),
        fake_distribution("Windows"),
        fake_distribution("NewPython"),
    ]
    graph = resolve_installed_graph(
        parse_package_requirements(['Root; python_version < "3.12"']),
        distributions=distributions,
        marker_environment=markers,
    )
    assert {p.name for p in graph.packages} == {"Root", "OldPython", "Windows"}


def test_probe_markers_match_packaging():
    from pip_fund._probe import snapshot

    data = snapshot()
    assert data["markers"] == default_environment()
    assert data["interpreter"] == sys.executable
    assert any("Name: pip-fund\n" in text for text in data["distributions"])
