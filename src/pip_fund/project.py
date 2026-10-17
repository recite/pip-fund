"""Select dependency roots from a Python project or environment."""

from __future__ import annotations

import tomllib
from collections import deque
from dataclasses import dataclass
from importlib import metadata
from typing import TYPE_CHECKING, Any

from packaging.markers import default_environment
from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name

from pip_fund.models import Failure, Package

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping
    from pathlib import Path


class ProjectError(ValueError):
    """Raised when project dependency configuration is invalid."""


@dataclass(frozen=True, slots=True)
class GraphResult:
    """Resolved installed dependency graph and its diagnostics."""

    packages: tuple[Package, ...]
    failures: tuple[Failure, ...]


@dataclass(slots=True)
class _NodeState:
    name: str
    version: str | None
    depth: int
    direct: bool
    parents: set[str]
    extras: set[str]
    expanded_extras: set[str]
    expanded_base: bool = False
    expanded_depth: int | None = None


def _normalize_group(name: str) -> str:
    return str(canonicalize_name(name))


def _dependency_groups(data: Mapping[str, Any], selected: Iterable[str]) -> list[str]:
    raw_groups = data.get("dependency-groups", {})
    if not isinstance(raw_groups, dict):
        raise ProjectError("[dependency-groups] must be a table")

    groups: dict[str, tuple[str, list[Any]]] = {}
    for raw_name, entries in raw_groups.items():
        normalized = _normalize_group(raw_name)
        if normalized in groups:
            previous = groups[normalized][0]
            raise ProjectError(
                f"dependency groups {previous!r} and {raw_name!r} "
                "normalize to the same name"
            )
        if not isinstance(entries, list):
            raise ProjectError(f"dependency group {raw_name!r} must be a list")
        groups[normalized] = (raw_name, entries)

    def expand(name: str, stack: tuple[str, ...]) -> list[str]:
        normalized = _normalize_group(name)
        if normalized not in groups:
            raise ProjectError(f"unknown dependency group: {name}")
        if normalized in stack:
            cycle = " -> ".join((*stack, normalized))
            raise ProjectError(f"dependency group include cycle: {cycle}")

        requirements: list[str] = []
        display_name, entries = groups[normalized]
        for entry in entries:
            if isinstance(entry, str):
                requirements.append(entry)
                continue
            if (
                isinstance(entry, dict)
                and set(entry) == {"include-group"}
                and isinstance(entry["include-group"], str)
            ):
                requirements.extend(
                    expand(entry["include-group"], (*stack, normalized))
                )
                continue
            raise ProjectError(
                f"invalid entry in dependency group {display_name!r}: {entry!r}"
            )
        return requirements

    requirements: list[str] = []
    for group in selected:
        requirements.extend(expand(group, ()))
    return requirements


def load_project_requirements(
    project_path: Path,
    *,
    extras: Iterable[str] = (),
    groups: Iterable[str] = (),
) -> tuple[str, list[Requirement]]:
    """Load direct requirements from standardized ``pyproject.toml`` fields."""
    pyproject = (
        project_path
        if project_path.name == "pyproject.toml"
        else project_path / "pyproject.toml"
    )
    if not pyproject.is_file():
        raise ProjectError(f"no pyproject.toml found at {pyproject}")

    try:
        data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise ProjectError(f"cannot read {pyproject}: {error}") from error

    if "project" not in data:
        raise ProjectError(
            "pyproject.toml has no [project] table; pass package requirements "
            "explicitly"
        )
    project = data["project"]
    if not isinstance(project, dict):
        raise ProjectError("[project] must be a table")
    project_name = project.get("name")
    scope = (
        f"project {project_name}"
        if isinstance(project_name, str)
        else f"project {pyproject.parent}"
    )

    dynamic = project.get("dynamic", [])
    if not isinstance(dynamic, list) or not all(
        isinstance(item, str) for item in dynamic
    ):
        raise ProjectError("project.dynamic must be a list of field names")
    if "dependencies" in dynamic:
        raise ProjectError(
            "project dependencies are dynamic; pass resolved package requirements "
            "explicitly"
        )

    raw_requirements = project.get("dependencies", [])
    if not isinstance(raw_requirements, list) or not all(
        isinstance(item, str) for item in raw_requirements
    ):
        raise ProjectError("project.dependencies must be a list of requirement strings")
    selected_requirements = list(raw_requirements)

    optional = project.get("optional-dependencies", {})
    if not isinstance(optional, dict):
        raise ProjectError("project.optional-dependencies must be a table")
    optional_by_name: dict[str, tuple[str, Any]] = {}
    for name, requirements in optional.items():
        normalized = _normalize_group(name)
        if normalized in optional_by_name:
            previous = optional_by_name[normalized][0]
            raise ProjectError(
                f"project extras {previous!r} and {name!r} normalize to the same name"
            )
        optional_by_name[normalized] = (name, requirements)
    for extra in extras:
        normalized = _normalize_group(extra)
        if normalized not in optional_by_name:
            raise ProjectError(f"unknown project extra: {extra}")
        display_name, requirements = optional_by_name[normalized]
        if not isinstance(requirements, list) or not all(
            isinstance(item, str) for item in requirements
        ):
            raise ProjectError(
                f"optional dependency group {display_name!r} must contain "
                "requirement strings"
            )
        selected_requirements.extend(requirements)

    selected_requirements.extend(_dependency_groups(data, groups))
    parsed: list[Requirement] = []
    for raw_requirement in selected_requirements:
        try:
            parsed.append(Requirement(raw_requirement))
        except InvalidRequirement as error:
            raise ProjectError(
                f"invalid requirement {raw_requirement!r}: {error}"
            ) from error
    return scope, parsed


def parse_package_requirements(values: Iterable[str]) -> list[Requirement]:
    """Parse package arguments as PEP 508 requirements."""
    parsed: list[Requirement] = []
    for value in values:
        try:
            parsed.append(Requirement(value))
        except InvalidRequirement as error:
            raise ProjectError(
                f"invalid package requirement {value!r}: {error}"
            ) from error
    return parsed


def _marker_applies(
    requirement: Requirement, extras: set[str], marker_environment: Mapping[str, str]
) -> bool:
    if requirement.marker is None:
        return True
    environment = dict(marker_environment)
    environment["extra"] = ""
    if requirement.marker.evaluate(environment, context="metadata"):
        return True
    for extra in extras:
        environment["extra"] = extra
        if requirement.marker.evaluate(environment, context="metadata"):
            return True
    return False


def _distribution_index(
    distributions: Iterable[metadata.Distribution] | None,
) -> dict[str, metadata.Distribution]:
    selected = metadata.distributions() if distributions is None else distributions
    index: dict[str, metadata.Distribution] = {}
    for distribution in selected:
        name = distribution.metadata["Name"]
        if name:
            index[str(canonicalize_name(name))] = distribution
    return index


def resolve_installed_graph(
    roots: Iterable[Requirement],
    *,
    distributions: Iterable[metadata.Distribution] | None = None,
    marker_environment: Mapping[str, str] | None = None,
) -> GraphResult:
    """Traverse installed ``Requires-Dist`` metadata from selected roots."""
    environment = (
        {key: str(value) for key, value in default_environment().items()}
        if marker_environment is None
        else marker_environment
    )
    index = _distribution_index(distributions)
    queue: deque[tuple[Requirement, str | None, int]] = deque(
        (requirement, None, 0) for requirement in roots
    )
    states: dict[str, _NodeState] = {}
    failures: list[Failure] = []

    while queue:
        requirement, parent, depth = queue.popleft()
        if parent is None and not _marker_applies(requirement, set(), environment):
            continue
        key = str(canonicalize_name(requirement.name))
        distribution = index.get(key)
        version = distribution.version if distribution is not None else None
        display_name = (
            distribution.metadata["Name"]
            if distribution is not None
            else requirement.name
        )

        state = states.get(key)
        if state is None:
            state = _NodeState(
                name=display_name,
                version=version,
                depth=depth,
                direct=depth == 0,
                parents=set(),
                extras=set(requirement.extras),
                expanded_extras=set(),
            )
            states[key] = state
        else:
            state.depth = min(state.depth, depth)
            state.direct = state.direct or depth == 0
            state.extras.update(requirement.extras)
        if parent:
            state.parents.add(parent)

        if distribution is None:
            if not any(
                failure.package == requirement.name
                and failure.message == "package is not installed"
                for failure in failures
            ):
                failures.append(
                    Failure(
                        package=requirement.name,
                        source="graph",
                        message="package is not installed",
                    )
                )
            continue

        if requirement.specifier and not requirement.specifier.contains(
            distribution.version, prereleases=True
        ):
            failures.append(
                Failure(
                    package=display_name,
                    source="graph",
                    message=(
                        f"installed version {distribution.version} does not satisfy "
                        f"{requirement.specifier}"
                    ),
                )
            )

        new_extras = state.extras - state.expanded_extras
        shorter_path = (
            state.expanded_depth is None or state.depth < state.expanded_depth
        )
        should_expand = not state.expanded_base or bool(new_extras) or shorter_path
        if not should_expand:
            continue
        state.expanded_base = True
        state.expanded_extras.update(new_extras)
        state.expanded_depth = state.depth

        for raw_child in distribution.requires or []:
            try:
                child = Requirement(raw_child)
            except InvalidRequirement as error:
                failures.append(
                    Failure(
                        package=display_name,
                        source="graph",
                        message=f"invalid Requires-Dist entry {raw_child!r}: {error}",
                    )
                )
                continue
            if _marker_applies(child, state.extras, environment):
                queue.append((child, display_name, state.depth + 1))

    packages = tuple(
        sorted(
            (
                Package(
                    name=state.name,
                    version=state.version,
                    direct=state.direct,
                    depth=state.depth,
                    parents=tuple(sorted(state.parents, key=str.casefold)),
                )
                for state in states.values()
            ),
            key=lambda package: (package.depth, package.name.casefold()),
        )
    )
    return GraphResult(packages=packages, failures=tuple(failures))


def installed_environment(
    *, distributions: Iterable[metadata.Distribution] | None = None
) -> tuple[Package, ...]:
    """Return every installed distribution for explicit environment audits."""
    index = _distribution_index(distributions)
    return tuple(
        sorted(
            (
                Package(
                    name=distribution.metadata["Name"],
                    version=distribution.version,
                    direct=None,
                    depth=None,
                )
                for distribution in index.values()
            ),
            key=lambda package: package.name.casefold(),
        )
    )
