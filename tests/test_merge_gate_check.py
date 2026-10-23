import io
import unittest
from contextlib import redirect_stdout

import merge_gate_check as mg


class ScanDiffTests(unittest.TestCase):
    def test_clean_diff_no_flags(self):
        diff = "+++ b/app.py\n+def add(a, b):\n+    return a + b\n+++ b/tests/test_app.py\n+def test_add():\n+    assert add(1, 2) == 3\n"
        self.assertEqual(mg.scan_diff(diff), [])
        self.assertEqual(mg.verdict([]), 'NO_HEURISTIC_FLAGS')

    def test_flags_possible_aws_key(self):
        diff = "+++ b/config.py\n+KEY = 'AKIAIOSFODNN7EXAMPLE'\n"
        kinds = [f['kind'] for f in mg.scan_diff(diff)]
        self.assertTrue(any('AWS' in k for k in kinds))

    def test_flags_possible_private_key(self):
        diff = "+++ b/key.pem\n+-----BEGIN RSA PRIVATE KEY-----\n"
        out = mg.scan_diff(diff)
        self.assertTrue(any('private key' in f['kind'] for f in out))
        self.assertIn('high-severity', mg.verdict(out))

    def test_flags_eval(self):
        diff = "+++ b/run.py\n+eval(user_input)\n"
        self.assertTrue(any('eval' in f['kind'] for f in mg.scan_diff(diff)))

    def test_source_without_tests_flagged(self):
        diff = "+++ b/app.py\n+x = 1\n"
        self.assertTrue(any('coverage gap' in f['kind'] for f in mg.scan_diff(diff)))

    def test_source_with_tests_not_flagged(self):
        diff = "+++ b/app.py\n+x = 1\n+++ b/tests/test_app.py\n+def test_x():\n+    assert True\n"
        self.assertFalse(any('coverage gap' in f['kind'] for f in mg.scan_diff(diff)))

    def test_removed_lines_ignored(self):
        diff = "+++ b/app.py\n-eval(user_input)\n"
        self.assertEqual(mg.scan_diff(diff), [])

    def test_json_cli(self):
        import sys
        argv = sys.argv
        sys.argv = ['merge_gate_check.py', '-', '--json']
        import json
        buf = io.StringIO()
        stdin = sys.stdin
        sys.stdin = io.StringIO("+++ b/a.py\n+eval(x)\n")
        try:
            with redirect_stdout(buf):
                mg.main()
            out = json.loads(buf.getvalue())
            self.assertEqual(out['verdict'], 'REVIEW_RECOMMENDED')
            self.assertTrue(any('eval' in f['kind'] for f in out['findings']))
        finally:
            sys.argv = argv
            sys.stdin = stdin


if __name__ == '__main__':
    unittest.main()
