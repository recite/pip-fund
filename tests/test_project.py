from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from pip_fund.project import (
    ProjectError,
    installed_environment,
    load_project_requirements,
    parse_package_requirements,
    resolve_installed_graph,
)
from tests.conftest import fake_distribution

if TYPE_CHECKING:
    from pathlib import Path

    from packaging.requirements import Requirement


def test_loads_runtime_extra_and_nested_dependency_group(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        """
[project]
name = "demo"
version = "1"
dependencies = ["runtime>=1"]

[project.optional-dependencies]
server = ["server-lib"]

[dependency-groups]
coverage = ["coverage"]
test = ["pytest", {include-group = "coverage"}]
""",
        encoding="utf-8",
    )

    scope, requirements = load_project_requirements(
        tmp_path, extras=["server"], groups=["test"]
    )

    assert scope == "project demo"
    assert [requirement.name for requirement in requirements] == [
        "runtime",
        "server-lib",
        "pytest",
        "coverage",
    ]


def test_rejects_dependency_group_cycle(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        """
[project]
name = "demo"
version = "1"

[dependency-groups]
a = [{include-group = "b"}]
b = [{include-group = "a"}]
""",
        encoding="utf-8",
    )

    with pytest.raises(ProjectError, match="include cycle"):
        load_project_requirements(tmp_path, groups=["a"])


def test_rejects_unknown_extra_and_group(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "demo"\nversion = "1"\n', encoding="utf-8"
    )

    with pytest.raises(ProjectError, match="unknown project extra"):
        load_project_requirements(tmp_path, extras=["missing"])
    with pytest.raises(ProjectError, match="unknown dependency group"):
        load_project_requirements(tmp_path, groups=["missing"])


def test_rejects_colliding_extra_names(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        """
[project]
name = "demo"
version = "1"

[project.optional-dependencies]
test_feature = []
test-feature = []
""",
        encoding="utf-8",
    )

    with pytest.raises(ProjectError, match="normalize to the same name"):
        load_project_requirements(tmp_path)


def test_rejects_invalid_project_requirements(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "demo"\nversion = "1"\ndependencies = ["not a req @"]\n',
        encoding="utf-8",
    )

    with pytest.raises(ProjectError, match="invalid requirement"):
        load_project_requirements(tmp_path)


def test_requires_a_pyproject_file(tmp_path: Path) -> None:
    with pytest.raises(ProjectError, match=r"no pyproject\.toml"):
        load_project_requirements(tmp_path)


def test_rejects_non_standard_and_dynamic_project_dependencies(tmp_path: Path) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text('[tool.poetry]\nname = "demo"\n', encoding="utf-8")
    with pytest.raises(ProjectError, match=r"no \[project\] table"):
        load_project_requirements(tmp_path)

    pyproject.write_text(
        '[project]\nname = "demo"\ndynamic = ["dependencies"]\n', encoding="utf-8"
    )
    with pytest.raises(ProjectError, match="dependencies are dynamic"):
        load_project_requirements(tmp_path)


def test_resolves_direct_and_transitive_dependencies() -> None:
    distributions = [
        fake_distribution(
            "Alpha", requires=["Bravo>=2", "ignored; python_version<'3'"]
        ),
        fake_distribution("Bravo", "2.1", requires=["Charlie"]),
        fake_distribution("Charlie", "3.0"),
    ]

    graph = resolve_installed_graph(
        load_requirements("Alpha"), distributions=distributions
    )

    assert [
        (package.name, package.depth, package.direct) for package in graph.packages
    ] == [
        ("Alpha", 0, True),
        ("Bravo", 1, False),
        ("Charlie", 2, False),
    ]
    assert graph.packages[1].parents == ("Alpha",)
    assert not graph.failures


def test_activates_dependency_extras() -> None:
    distributions = [
        fake_distribution("Alpha", requires=["Bravo; extra == 'server'", "Core"]),
        fake_distribution("Bravo"),
        fake_distribution("Core"),
    ]

    graph = resolve_installed_graph(
        load_requirements("Alpha[server]"), distributions=distributions
    )

    assert {package.name for package in graph.packages} == {"Alpha", "Bravo", "Core"}


def test_reports_missing_and_incompatible_packages() -> None:
    graph = resolve_installed_graph(
        load_requirements("Alpha>=2", "Missing"),
        distributions=[fake_distribution("Alpha", "1.0")],
    )

    assert {package.name for package in graph.packages} == {"Alpha", "Missing"}
    assert {failure.package for failure in graph.failures} == {"Alpha", "Missing"}
    assert any("does not satisfy" in failure.message for failure in graph.failures)
    assert any("not installed" in failure.message for failure in graph.failures)


def test_dependency_cycle_terminates() -> None:
    distributions = [
        fake_distribution("Alpha", requires=["Bravo"]),
        fake_distribution("Bravo", requires=["Alpha"]),
    ]

    graph = resolve_installed_graph(
        load_requirements("Alpha"), distributions=distributions
    )

    assert [package.name for package in graph.packages] == ["Alpha", "Bravo"]
    assert graph.packages[0].direct


def test_uses_shortest_dependency_depth() -> None:
    distributions = [
        fake_distribution("Root", requires=["Long", "Target"]),
        fake_distribution("Long", requires=["Middle"]),
        fake_distribution("Middle", requires=["Target"]),
        fake_distribution("Target", requires=["Leaf"]),
        fake_distribution("Leaf"),
    ]

    graph = resolve_installed_graph(
        load_requirements("Root"), distributions=distributions
    )
    depths = {package.name: package.depth for package in graph.packages}

    assert depths["Target"] == 1
    assert depths["Leaf"] == 2


def test_reports_invalid_installed_requirement_metadata() -> None:
    graph = resolve_installed_graph(
        load_requirements("Alpha"),
        distributions=[fake_distribution("Alpha", requires=["not a req @"])],
    )

    assert len(graph.failures) == 1
    assert "invalid Requires-Dist" in graph.failures[0].message


def test_lists_an_installed_environment() -> None:
    packages = installed_environment(
        distributions=[fake_distribution("Zulu", "2"), fake_distribution("Alpha", "1")]
    )

    assert [(package.name, package.version) for package in packages] == [
        ("Alpha", "1"),
        ("Zulu", "2"),
    ]


def load_requirements(*values: str) -> list[Requirement]:
    return parse_package_requirements(values)
