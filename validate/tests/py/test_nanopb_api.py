"""After a nanopb upgrade: everything this tool uses from nanopb is still there.

nanopb_api.py lists it (generator functions and classes, options, files). If
this test fails after merging a new nanopb, fix nanopb_api.py (and only the
validate/ folder); nanopb's own files stay as upstream ships them.
"""

import glob
import os
import re
import unittest

from helpers import PKG_DIR

import nanopb_api


class NanopbApiTests(unittest.TestCase):
    def test_everything_used_from_nanopb_exists(self):
        self.assertEqual(nanopb_api.check(), [])

    def test_only_the_adapter_imports_nanopb(self):
        """nanopb is imported in two places only: env.py (paths, _pb2 build) and nanopb_api.py."""

        offenders = []
        for path in glob.glob(os.path.join(PKG_DIR, '*.py')):
            name = os.path.basename(path)
            if name in ('env.py', 'nanopb_api.py'):
                continue
            with open(path, encoding='utf-8') as handle:
                text = handle.read()
            if re.search(r'^\s*(import nanopb_generator\b|from proto\b|import proto\b)', text, re.M):
                offenders.append(name)
        self.assertEqual(offenders, [], 'import nanopb through nanopb_api.py instead')


if __name__ == '__main__':
    unittest.main()
