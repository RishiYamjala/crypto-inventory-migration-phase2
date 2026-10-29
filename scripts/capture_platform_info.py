#!/usr/bin/env python3
"""Capture runtime and pinned-package metadata without inventing host details."""
from __future__ import annotations

import argparse
import importlib.metadata
import json
import os
import platform
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _pinned_requirements(path: Path) -> dict[str, str]:
    pinned: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        match = re.match(r"^([A-Za-z0-9_.-]+)==([^;\s]+)", line)
        if match:
            pinned[match.group(1).lower().replace("_", "-")] = match.group(2)
    return pinned


def _memory_bytes() -> int | None:
    try:
        if hasattr(os, "sysconf"):
            pages = os.sysconf("SC_PHYS_PAGES")
            page_size = os.sysconf("SC_PAGE_SIZE")
            if isinstance(pages, int) and isinstance(page_size, int) and pages > 0 and page_size > 0:
                return pages * page_size
    except (OSError, ValueError, AttributeError):
        pass
    return None


def collect_platform_info() -> dict:
    pinned = _pinned_requirements(ROOT / "requirements.txt")
    installed: dict[str, dict[str, str | None]] = {}
    for normalized_name, expected_version in sorted(pinned.items()):
        try:
            version = importlib.metadata.version(normalized_name)
        except importlib.metadata.PackageNotFoundError:
            version = None
        installed[normalized_name] = {
            "pinned_version": expected_version,
            "installed_version": version,
            "matches_pin": str(version == expected_version).lower(),
        }

    github = {}
    for key in ("GITHUB_ACTIONS", "GITHUB_WORKFLOW", "GITHUB_RUN_ID", "GITHUB_RUN_NUMBER", "GITHUB_SHA", "RUNNER_OS", "RUNNER_ARCH"):
        value = os.environ.get(key)
        if value:
            github[key.lower()] = value

    return {
        "schema_version": "1.0",
        "profile_name": "runtime-captured environment",
        "capture_status": "runtime_captured",
        "captured_at_utc": datetime.now(timezone.utc).isoformat(),
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "processor": platform.processor() or None,
            "cpu_count": os.cpu_count(),
            "memory_bytes": _memory_bytes(),
        },
        "python": {
            "version": platform.python_version(),
            "implementation": platform.python_implementation(),
            "executable_name": Path(sys.executable).name,
        },
        "github_actions": github,
        "dependencies": installed,
        "official_environment_check": {
            "expected_path": "common/env_check.py",
            "present_in_checkout": (ROOT / "common" / "env_check.py").exists(),
            "status": "not_run",
            "note": "Runtime capture does not replace the organizer's environment checker or its schema.",
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="platform_A_info.json", help="Output JSON path")
    args = parser.parse_args()
    target = Path(args.output)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(collect_platform_info(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Wrote runtime platform information to {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
