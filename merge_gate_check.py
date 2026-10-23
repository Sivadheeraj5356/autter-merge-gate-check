#!/usr/bin/env python3
"""merge-gate-check: a heuristic pre-merge risk checker for pull requests.

Inspired by Autter's merge-gate concept (code security & assurance layer):
before a change merges, flag *potential* issues so a human can look closer.

IMPORTANT: this tool uses static heuristics only. It does NOT execute code,
run tests, or verify behavior. Findings are POSSIBLE issues, not verdicts.
See README Limitations.
"""
import argparse
import json
import re
import sys

SECRET_PATTERNS = [
    (re.compile(r'AKIA[0-9A-Z]{16}'), 'possible AWS access key'),
    (re.compile(r'sk-[A-Za-z0-9]{20,}'), 'possible API token (sk-...)'),
    (re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----'), 'possible private key block'),
    (re.compile(r'(?i)(password|passwd|secret)\s*=\s*["\'][^"\']{6,}["\']'), 'possible hardcoded credential'),
]
RISK_HINTS = [
    (re.compile(r'\beval\s*\('), 'uses eval() - review for injection risk'),
    (re.compile(r'\bexec\s*\('), 'uses exec() - review for injection risk'),
    (re.compile(r'subprocess.*shell\s*=\s*True'), 'subprocess with shell=True - review quoting'),
    (re.compile(r'(?i)todo|fixme|hack'), 'leftover TODO/FIXME/HACK marker'),
]
TEST_FILE_RE = re.compile(r'(?i)(test_|_test|tests?/|spec_)')

def scan_diff(diff_text):
    """Scan unified-diff text. Returns list of heuristic findings."""
    findings = []
    added_test_lines = 0
    added_src_lines = 0
    files = set()
    current_file = None
    for line in diff_text.splitlines():
        if line.startswith('+++ b/'):
            current_file = line[6:]
            files.add(current_file)
            continue
        if not line.startswith('+') or line.startswith('+++'):
            continue
        body = line[1:]
        if current_file and TEST_FILE_RE.search(current_file):
            added_test_lines += 1
        else:
            added_src_lines += 1
        for rx, label in SECRET_PATTERNS + RISK_HINTS:
            if rx.search(body):
                findings.append({
                    'file': current_file,
                    'kind': label,
                    'line_preview': body.strip()[:80],
                })
    if added_src_lines > 0 and added_test_lines == 0:
        findings.append({
            'file': None,
            'kind': 'source changes without accompanying test changes (possible coverage gap)',
            'line_preview': '',
        })
    return findings

def verdict(findings):
    if any('private key' in f['kind'] or 'AWS access key' in f['kind'] for f in findings):
        return 'REVIEW_RECOMMENDED (high-severity heuristic hits)'
    if findings:
        return 'REVIEW_RECOMMENDED'
    return 'NO_HEURISTIC_FLAGS'

def main():
    ap = argparse.ArgumentParser(description='Heuristic pre-merge risk check for a unified diff.')
    ap.add_argument('diff', help='Path to a .diff/.patch file, or - for stdin')
    ap.add_argument('--json', action='store_true', help='Emit JSON findings')
    args = ap.parse_args()
    text = sys.stdin.read() if args.diff == '-' else open(args.diff).read()
    findings = scan_diff(text)
    if args.json:
        print(json.dumps({'verdict': verdict(findings), 'findings': findings}, indent=2))
    else:
        print(verdict(findings))
        for f in findings:
            print(f"- {f['kind']}" + (f" ({f['file']}: {f['line_preview']})" if f['file'] else ''))
    return 0

if __name__ == '__main__':
    sys.exit(main())
