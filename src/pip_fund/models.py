"""Data structures shared by dependency and funding discovery."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

FundingSource = Literal["metadata", "pypi", "github"]
FailureSource = Literal["project", "graph", "metadata", "pypi", "github"]


@dataclass(frozen=True, slots=True)
class Package:
    """A package in the selected dependency graph."""

    name: str
    version: str | None
    direct: bool | None
    depth: int | None
    parents: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class FundingRecord:
    """A funding declaration associated with one package."""

    package: str
    label: str
    url: str
    canonical_url: str
    source: FundingSource


@dataclass(frozen=True, slots=True)
class Failure:
    """A non-fatal problem that made a report incomplete."""

    package: str | None
    source: FailureSource
    message: str


@dataclass(frozen=True, slots=True)
class Destination:
    """Funding records grouped by their canonical destination URL."""

    url: str
    records: tuple[FundingRecord, ...]


@dataclass(slots=True)
class Report:
    """Complete result of one funding audit."""

    scope: str
    packages: tuple[Package, ...]
    records: tuple[FundingRecord, ...]
    failures: tuple[Failure, ...] = ()
    interpreter: str | None = None
    _destinations: tuple[Destination, ...] | None = field(
        default=None, init=False, repr=False
    )

    @property
    def destinations(self) -> tuple[Destination, ...]:
        """Return records grouped deterministically by canonical URL."""
        if self._destinations is None:
            grouped: dict[str, list[FundingRecord]] = {}
            for record in self.records:
                grouped.setdefault(record.canonical_url, []).append(record)
            self._destinations = tuple(
                Destination(
                    url=url,
                    records=tuple(
                        sorted(
                            records,
                            key=lambda item: (
                                item.package.casefold(),
                                item.source,
                                item.label.casefold(),
                            ),
                        )
                    ),
                )
                for url, records in sorted(grouped.items())
            )
        return self._destinations

    @property
    def funded_package_count(self) -> int:
        """Return the number of distinct packages with funding records."""
        return len({record.package.casefold() for record in self.records})
