"""Command line entry point: python -m sigma_lab.cli [rules_dir] [fixtures_dir]

Checks that every rule is well formed, then replays labelled events against it.
Exit code is non-zero if any rule is invalid, any fixture is missing, or any
event is classified the wrong way. That makes it usable as a CI gate.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from .engine import load_rule, matches, validate_rule


def run(rules_dir: Path, fixtures_dir: Path) -> int:
    failures = 0
    rule_files = sorted(rules_dir.glob("*.yml"))
    if not rule_files:
        print(f"no rules found in {rules_dir}")
        return 1
    for rule_file in rule_files:
        rule = load_rule(rule_file)
        problems = validate_rule(rule)
        fixture_file = fixtures_dir / f"{rule_file.stem}.json"
        if not fixture_file.exists():
            problems.append(f"no fixture file: {fixture_file.name}")
        cases = json.loads(fixture_file.read_text()) if fixture_file.exists() else []
        if fixture_file.exists():
            if not any(c["expect"] for c in cases):
                problems.append("fixtures contain no true positive")
            if not any(not c["expect"] for c in cases):
                problems.append("fixtures contain no benign case")
        for case in cases:
            got = matches(rule, case["event"])
            if got != case["expect"]:
                problems.append(f"fixture '{case['name']}': expected {case['expect']}, got {got}")
        status = "FAIL" if problems else "ok  "
        print(f"{status} {rule_file.name}  ({len(cases)} cases)")
        for problem in problems:
            print(f"       - {problem}")
        failures += bool(problems)
    print(f"\n{len(rule_files) - failures}/{len(rule_files)} rules passed")
    return 1 if failures else 0


def main() -> None:
    rules = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("rules")
    fixtures = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("tests/fixtures")
    sys.exit(run(rules, fixtures))


if __name__ == "__main__":
    main()
