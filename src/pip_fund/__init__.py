"""Audit funding declarations across Python project dependencies."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("pip-fund")
except PackageNotFoundError:  # pragma: no cover
    __version__ = "0+unknown"

__all__ = ["__version__"]
