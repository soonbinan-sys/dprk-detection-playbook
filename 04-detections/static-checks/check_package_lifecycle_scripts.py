#!/usr/bin/env python3
"""
check_package_lifecycle_scripts.py

Static check for a single package.json, or a directory scanned for them.

Flags:
  1. Any preinstall, install, or postinstall lifecycle script. Not
     inherently malicious, most hits will be legitimate native module
     builds, but it is the exact mechanism used in the UNC1069 axios
     compromise and across the Contagious Interview npm campaigns, so
     it is worth a human look every time.
  2. Dependency names matching a small, rotating list of publicly
     reported malicious package names. IOC based, update the list as
     new campaigns are reported, do not treat an empty result as clean.

Usage:
  python3 check_package_lifecycle_scripts.py path/to/package.json
  python3 check_package_lifecycle_scripts.py path/to/project/
"""

import json
import sys
from pathlib import Path

LIFECYCLE_SCRIPTS = {"preinstall", "install", "postinstall"}

# Rotate this list as new campaigns are publicly reported.
# Source: 01-research/sources.md
KNOWN_MALICIOUS_PACKAGE_NAMES = {
    "plain-crypto-js",
}


def check_package_json(path: Path) -> list:
    findings = []
    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        return [f"could not read {path}: {exc}"]

    scripts = data.get("scripts", {})
    hit_lifecycle = LIFECYCLE_SCRIPTS.intersection(scripts.keys())
    if hit_lifecycle:
        findings.append(
            f"{path}: defines lifecycle script(s) {sorted(hit_lifecycle)}, review manually"
        )

    deps = {}
    for key in ("dependencies", "devDependencies", "optionalDependencies"):
        deps.update(data.get(key, {}))

    hit_known = KNOWN_MALICIOUS_PACKAGE_NAMES.intersection(deps.keys())
    if hit_known:
        findings.append(
            f"{path}: dependency list includes known malicious package name(s) {sorted(hit_known)}"
        )

    return findings


def main(argv: list) -> int:
    if len(argv) != 2:
        print(__doc__)
        return 1

    target = Path(argv[1])
    if target.is_file():
        package_files = [target]
    else:
        package_files = [
            p for p in target.rglob("package.json") if "node_modules" not in p.parts
        ]

    if not package_files:
        print(f"no package.json found under {target}")
        return 0

    all_findings = []
    for package_file in package_files:
        all_findings.extend(check_package_json(package_file))

    if not all_findings:
        print(f"checked {len(package_files)} package.json file(s), no findings")
        return 0

    for finding in all_findings:
        print(finding)
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
