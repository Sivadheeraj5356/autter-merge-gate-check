# autter-merge-gate-check

A small heuristic pre-merge risk checker for pull-request diffs, built as a
take-home-style companion to Autter (the code security & assurance layer for
the AI coding era). Autter's merge gate runs changes in a sandbox and holds
the merge until checks pass; this tool is a lightweight static companion that
scans a unified diff and flags *potential* issues for human review before a
change gets that far.

## What it does

- Scans a unified diff (`.diff`/`.patch` or stdin) for heuristic risk signals:
  - Possible credentials: AWS-style access keys, `sk-...` tokens, private key
    blocks, hardcoded password/secret assignments
  - Risky constructs: `eval()`/`exec()`, `subprocess` with `shell=True`,
    leftover TODO/FIXME/HACK markers
  - Source changes with no accompanying test changes (possible coverage gap)
- Emits a verdict: `NO_HEURISTIC_FLAGS` or `REVIEW_RECOMMENDED`
  (with a high-severity note for possible keys).

## Usage

```bash
python3 merge_gate_check.py my-change.diff
git diff main...feature | python3 merge_gate_check.py - --json
python3 -m unittest discover -s tests   # run the test suite
```

## Limitations

Heuristics produce false positives by design; the verdict is a review hint,
not a security proof. It does not execute code and does not replace Autter's
sandboxed merge gate - it complements it one step earlier in the flow.

## Tests

`python3 -m unittest discover -s tests` - 8 tests covering credential
patterns, risky constructs, the coverage-gap heuristic, verdict mapping and
JSON output.

Built by Siva Dheeraj (github.com/Sivadheeraj5356) as a company-specific
project for the Autter Backend Engineer (Agentic AI) application.
