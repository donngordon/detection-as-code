import json
from pathlib import Path

import pytest

from sigma_lab import load_rule, matches, validate_rule
from sigma_lab.engine import RuleError, _Parser

ROOT = Path(__file__).resolve().parent.parent
RULES = sorted((ROOT / "rules").glob("*.yml"))


@pytest.mark.parametrize("path", RULES, ids=lambda p: p.stem)
def test_rule_is_valid(path):
    assert validate_rule(load_rule(path)) == []


def _cases():
    for path in RULES:
        fixture = ROOT / "tests" / "fixtures" / f"{path.stem}.json"
        for case in json.loads(fixture.read_text()):
            yield pytest.param(path, case, id=f"{path.stem}::{case['name']}")


@pytest.mark.parametrize("path,case", list(_cases()))
def test_fixture(path, case):
    assert matches(load_rule(path), case["event"]) is case["expect"]


def test_condition_precedence_and_grouping():
    names = ["a", "b", "c"]
    assert _Parser("a or b and c", names).parse() == ("or", ("sel", "a"), ("and", ("sel", "b"), ("sel", "c")))
    assert _Parser("(a or b) and not c", names).parse() == (
        "and", ("or", ("sel", "a"), ("sel", "b")), ("not", ("sel", "c")))


def test_unknown_selection_is_rejected():
    with pytest.raises(RuleError):
        _Parser("a and missing", ["a"]).parse()


def test_unsupported_modifier_is_rejected():
    rule = {"detection": {"s": {"Image|re": "x"}, "condition": "s"}}
    with pytest.raises(RuleError):
        matches(rule, {"Image": "x"})


def test_one_of_pattern():
    rule = {"detection": {"sel_a": {"X": "1"}, "sel_b": {"X": "2"}, "condition": "1 of sel_*"}}
    assert matches(rule, {"X": "2"})
    assert not matches(rule, {"X": "3"})
