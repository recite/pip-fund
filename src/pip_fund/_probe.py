"""Read installed metadata using only the target interpreter's standard library."""

from __future__ import annotations

import json
import os
import platform
import sys
from importlib import metadata


def snapshot() -> dict[str, object]:
    """Return installed metadata and the target's dependency marker environment."""
    version = sys.implementation.version
    implementation_version = f"{version.major}.{version.minor}.{version.micro}"
    if version.releaselevel != "final":
        implementation_version += f"{version.releaselevel[0]}{version.serial}"
    markers = {
        "implementation_name": sys.implementation.name,
        "implementation_version": implementation_version,
        "os_name": os.name,
        "platform_machine": platform.machine(),
        "platform_release": platform.release(),
        "platform_system": platform.system(),
        "platform_version": platform.version(),
        "python_full_version": platform.python_version(),
        "platform_python_implementation": platform.python_implementation(),
        "python_version": ".".join(platform.python_version_tuple()[:2]),
        "sys_platform": sys.platform,
    }
    distributions = [
        distribution.read_text("METADATA") or distribution.read_text("PKG-INFO") or ""
        for distribution in metadata.distributions()
    ]
    return {
        "interpreter": sys.executable,
        "markers": markers,
        "distributions": distributions,
    }


if __name__ == "__main__":
    print(json.dumps(snapshot()))  # noqa: T201
