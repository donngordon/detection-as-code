"""A small, readable evaluator for a practical subset of Sigma.

Supported
  * selections as a map (all fields must match) or a list of maps (any may match)
  * field modifiers: contains, startswith, endswith, all
  * case-insensitive matching, as in Sigma
  * conditions: and, or, not, parentheses, "1 of <glob>", "all of <glob>", "them"

Not supported: aggregations (count, near), regex and CIDR modifiers, field-name
mapping. Use pySigma for production conversion. This engine exists so detection
logic can be unit tested in CI with no SIEM running.
"""

from __future__ import annotations

import fnmatch
import re
from pathlib import Path
from typing import Any

import yaml

REQUIRED_KEYS = ("title", "id", "logsource", "detection", "level")
VALID_LEVELS = {"informational", "low", "medium", "high", "critical"}


class RuleError(ValueError):
    """Raised when a rule is malformed or uses an unsupported feature."""


def load_rule(path: str | Path) -> dict[str, Any]:
    rule = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(rule, dict):
        raise RuleError(f"{path}: rule must be a YAML mapping")
    return rule


def validate_rule(rule: dict[str, Any]) -> list[str]:
    """Return a list of problems. An empty list means the rule is valid."""
    problems = [f"missing key: {k}" for k in REQUIRED_KEYS if k not in rule]
    if rule.get("level") not in VALID_LEVELS and "level" in rule:
        problems.append(f"invalid level: {rule['level']!r}")
    detection = rule.get("detection")
    if isinstance(detection, dict):
        if "condition" not in detection:
            problems.append("detection has no condition")
        else:
            try:
                names = [k for k in detection if k != "condition"]
                _Parser(detection["condition"], names).parse()
            except RuleError as exc:
                problems.append(str(exc))
    tags = rule.get("tags", [])
    if not any(str(t).startswith("attack.t") for t in tags):
        problems.append("no ATT&CK technique tag (attack.tNNNN)")
    return problems


# ---------------------------------------------------------------- matching

def _field_matches(event_value: Any, modifiers: list[str], expected: Any) -> bool:
    values = expected if isinstance(expected, list) else [expected]
    if event_value is None:
        return False
    text = str(event_value).lower()
    results = []
    for value in values:
        needle = str(value).lower()
        if "contains" in modifiers:
            results.append(needle in text)
        elif "startswith" in modifiers:
            results.append(text.startswith(needle))
        elif "endswith" in modifiers:
            results.append(text.endswith(needle))
        else:
            results.append(text == needle)
    return all(results) if "all" in modifiers else any(results)


def _match_map(mapping: dict[str, Any], event: dict[str, Any]) -> bool:
    for key, expected in mapping.items():
        field, *modifiers = key.split("|")
        unknown = set(modifiers) - {"contains", "startswith", "endswith", "all"}
        if unknown:
            raise RuleError(f"unsupported modifier(s) on {field}: {sorted(unknown)}")
        if not _field_matches(event.get(field), modifiers, expected):
            return False
    return True


def _match_selection(selection: Any, event: dict[str, Any]) -> bool:
    if isinstance(selection, dict):
        return _match_map(selection, event)
    if isinstance(selection, list):
        return any(_match_map(item, event) for item in selection)
    raise RuleError("a selection must be a map or a list of maps")


# --------------------------------------------------------------- conditions

_TOKEN = re.compile(r"\(|\)|[^\s()]+")


class _Parser:
    """Recursive descent parser. Precedence: not > and > or."""

    def __init__(self, condition: str, selection_names: list[str]):
        self.tokens = _TOKEN.findall(str(condition))
        self.names = selection_names
        self.pos = 0

    def parse(self):
        node = self._or()
        if self.pos != len(self.tokens):
            raise RuleError(f"unexpected token in condition: {self.tokens[self.pos]!r}")
        return node

    def _peek(self):
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _next(self):
        token = self._peek()
        self.pos += 1
        return token

    def _or(self):
        node = self._and()
        while (self._peek() or "").lower() == "or":
            self._next()
            node = ("or", node, self._and())
        return node

    def _and(self):
        node = self._not()
        while (self._peek() or "").lower() == "and":
            self._next()
            node = ("and", node, self._not())
        return node

    def _not(self):
        if (self._peek() or "").lower() == "not":
            self._next()
            return ("not", self._not())
        return self._atom()

    def _atom(self):
        token = self._next()
        if token is None:
            raise RuleError("condition ended unexpectedly")
        if token == "(":
            node = self._or()
            if self._next() != ")":
                raise RuleError("missing closing parenthesis")
            return node
        if token.lower() in ("1", "all") and (self._peek() or "").lower() == "of":
            self._next()
            pattern = self._next()
            if pattern is None:
                raise RuleError("'of' needs a selection pattern")
            matched = (
                list(self.names) if pattern == "them"
                else [n for n in self.names if fnmatch.fnmatch(n, pattern)]
            )
            if not matched:
                raise RuleError(f"pattern {pattern!r} matches no selection")
            return ("all_of" if token.lower() == "all" else "one_of", matched)
        if token not in self.names:
            raise RuleError(f"condition refers to unknown selection: {token!r}")
        return ("sel", token)


def _evaluate(node, detection: dict[str, Any], event: dict[str, Any]) -> bool:
    kind = node[0]
    if kind == "sel":
        return _match_selection(detection[node[1]], event)
    if kind == "not":
        return not _evaluate(node[1], detection, event)
    if kind == "and":
        return _evaluate(node[1], detection, event) and _evaluate(node[2], detection, event)
    if kind == "or":
        return _evaluate(node[1], detection, event) or _evaluate(node[2], detection, event)
    results = [_match_selection(detection[n], event) for n in node[1]]
    return all(results) if kind == "all_of" else any(results)


def matches(rule: dict[str, Any], event: dict[str, Any]) -> bool:
    """Return True when the event triggers the rule."""
    detection = rule["detection"]
    names = [k for k in detection if k != "condition"]
    tree = _Parser(detection["condition"], names).parse()
    return _evaluate(tree, detection, event)
