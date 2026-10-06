# detection-as-code

Sigma detection rules with a small test harness, so every rule is **validated and unit tested in CI** before it ships. No SIEM required.

Detection rules are software. They need version control, review and tests, otherwise a typo quietly turns a detection into a no-op. This repo shows that workflow end to end.

## What is in here

| Path | Purpose |
|---|---|
| `rules/` | Sigma rules mapped to MITRE ATT&CK |
| `tests/fixtures/` | Labelled events per rule: true positives and benign look-alikes |
| `sigma_lab/` | Small Sigma-subset evaluator and CLI |
| `.github/workflows/ci.yml` | Runs validation, fixture replay and pytest on every push |

## Rules

| Rule | ATT&CK | Level |
|---|---|---|
| Encoded PowerShell command | T1059.001 | medium |
| Suspicious process access to LSASS | T1003.001 | high |
| Remote service creation via sc.exe | T1021.002, T1569.002 | medium |

## How it works

`python -m sigma_lab.cli` will:

1. validate each rule (required fields, valid level, parseable condition, ATT&CK tag)
2. require a fixture file with at least one true positive and one benign case
3. replay every labelled event and fail if a rule gets any of them wrong

Exit code is non-zero on any failure, so it works as a merge gate.

```bash
pip install -r requirements.txt
python -m sigma_lab.cli
pytest -q
```

## Adding a rule

1. Add `rules/<name>.yml`.
2. Add `tests/fixtures/<name>.json`: a list of `{"name", "expect", "event"}`.
3. Open a PR. CI tells you if the rule is malformed or misclassifies an event.

## Limits (read this)

The evaluator supports a practical **subset** of Sigma: map and list selections, the modifiers `contains`, `startswith`, `endswith` and `all`, case-insensitive matching, and conditions with `and`, `or`, `not`, parentheses and `1 of` / `all of`. It does **not** support aggregations, regex or CIDR modifiers, or field mapping. Unsupported modifiers raise an error instead of silently passing.

For production, convert rules with [pySigma](https://github.com/SigmaHQ/pySigma) to your SIEM's query language. This harness exists to test detection *logic* quickly and locally.

## Author

Donn Gordon, Detection Engineering. [LinkedIn](https://www.linkedin.com/in/donn-gordon-120607117/) · [GitHub](https://github.com/donngordon)
