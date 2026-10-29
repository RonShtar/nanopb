"""Runs examples/stress/stress_test.py: merged C for a 6-proto unit, samples for
every message, C round trip (when a compiler is available) and tshark
dissection of the showcase + sample packets (when tshark is available).
"""

import os
import shutil
import sys
import tempfile
import unittest

from helpers import TOOL_DIR

sys.path.insert(0, os.path.join(TOOL_DIR, 'examples', 'stress'))
import stress_test  # noqa: E402


class StressTests(unittest.TestCase):
    def test_stress_example(self):
        out = tempfile.mkdtemp(prefix='nanopb_ws_stress_')
        try:
            self.assertEqual(stress_test.main(['--out', out, '--count', '2']), 0)
            self.assertTrue(os.path.isfile(os.path.join(out, 'fleet', 'fleet.c')))
            self.assertTrue(os.path.isfile(os.path.join(out, 'stress.pcap')))
        finally:
            shutil.rmtree(out, ignore_errors=True)


if __name__ == '__main__':
    unittest.main()
