"""Real-Wireshark regression test: dissect the live test capture with tshark.

Skipped unless tshark is found (PATH, TSHARK=<path>, or the default
Windows install folder). Loads the dissector from this repository with
`-X lua_script:`, so it is also skipped when a copy is installed in the
personal plugins folder (the two would clash); use
`live_test.py verify` for that setup.
"""

import os
import shutil
import sys
import tempfile
import unittest

from helpers import TESTS_DIR

sys.path.insert(0, os.path.join(TESTS_DIR, 'live'))
import cases as live_cases  # noqa: E402
import live_test  # noqa: E402

TSHARK = live_test.find_tshark()


@unittest.skipIf(TSHARK is None, 'tshark not found')
@unittest.skipIf(live_test.installed_dissector() is not None,
                 'nanopb_any_dissector.lua installed in personal plugins; run live_test.py verify instead')
class TsharkTests(unittest.TestCase):
    def test_live_capture(self):
        tmp = tempfile.mkdtemp(prefix='nanopb_ws_tshark_')
        try:
            cases = live_cases.all_cases(generated=3)
            pcap = os.path.join(tmp, 'live.pcap')
            live_test.write_pcap(pcap, cases)
            results = live_test.verify(pcap, cases, isolated=True)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        failures = ['%d %s: %s' % (n, c.name, '; '.join(p)) for n, c, p in results if p]
        self.assertEqual(failures, [])


if __name__ == '__main__':
    unittest.main()
