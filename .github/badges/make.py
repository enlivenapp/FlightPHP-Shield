#!/usr/bin/env python3
"""Turn raw tool output into a shields.io endpoint badge.

Usage: make.py <tool> <input-file> <output-file>

Supported tools: phpunit, phpstan, psalm, infection.
A badge is always written. Unreadable input yields a grey "no result" badge, so
a broken run never leaves a stale or blank button in the README.
"""

from __future__ import annotations

import json
import pathlib
import re
import sys


def read(path: str) -> str:
    try:
        return pathlib.Path(path).read_text(errors="replace")
    except OSError:
        return ""


def count(text: str, field: str) -> int:
    hits = re.findall(rf"\b{field}:\s*(\d+)", text)
    return int(hits[-1]) if hits else 0


def phpunit(input_path: str) -> tuple[str, str]:
    text = read(input_path)
    tests = count(text, "Tests")
    if tests == 0:
        return "no result", "lightgrey"
    assertions = count(text, "Assertions")
    skipped = count(text, "Skipped")
    bad = count(text, "Failures") + count(text, "Errors") + count(text, "Risky")
    color = "brightgreen" if bad == 0 else "red"
    return f"{tests} tests | {assertions} assertions | {skipped} skipped", color


def phpstan(input_path: str) -> tuple[str, str]:
    try:
        errors = int(json.loads(read(input_path))["totals"]["file_errors"])
    except (ValueError, KeyError, TypeError):
        return "no result", "lightgrey"
    level = re.search(r"level:\s*(\d+)", read("phpstan.neon"))
    return f"level {level.group(1) if level else '?'} | {errors} errors", (
        "brightgreen" if errors == 0 else "red"
    )


def psalm(input_path: str) -> tuple[str, str]:
    text = read(input_path).strip()
    try:
        issues = json.loads(text)
    except ValueError:
        return "no result", "lightgrey"
    if isinstance(issues, dict):
        issues = issues.get("issues", [])
    errors = len(issues)
    level = re.search(r'errorLevel="(\d+)"', read("psalm.xml"))
    suffix = "error" if errors == 1 else "errors"
    return f"level {level.group(1) if level else '?'} | {errors} {suffix}", (
        "brightgreen" if errors == 0 else "red"
    )


def infection(input_path: str) -> tuple[str, str]:
    try:
        stats = json.loads(read(input_path))["stats"]
        msi = round(float(stats["msi"]))
        coverage = round(float(stats["mutationCodeCoverage"]))
    except (ValueError, KeyError, TypeError):
        return "no result", "lightgrey"
    if msi >= 80:
        color = "brightgreen"
    elif msi >= 60:
        color = "green"
    elif msi >= 40:
        color = "yellow"
    else:
        color = "red"
    return f"MSI {msi}% | {coverage}% coverage", color


TOOLS = {
    "phpunit": ("PHPUnit", phpunit),
    "phpstan": ("PHPStan", phpstan),
    "psalm": ("Psalm", psalm),
    "infection": ("Infection", infection),
}


def main() -> int:
    if len(sys.argv) != 4 or sys.argv[1] not in TOOLS:
        print(f"usage: {sys.argv[0]} <{'|'.join(TOOLS)}> <input> <output>", file=sys.stderr)
        return 2

    label, build = TOOLS[sys.argv[1]]
    try:
        message, color = build(sys.argv[2])
    except Exception:  # noqa: BLE001 - the badge must always be written
        message, color = "no result", "lightgrey"

    badge = {
        "schemaVersion": 1,
        "label": label,
        "message": message,
        "color": color,
    }
    pathlib.Path(sys.argv[3]).write_text(json.dumps(badge) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
