"""Real-Wireshark regression test: dissect the live test capture with tshark.

Skipped unless tshark is found (PATH, TSHARK=<path>, or the default
Windows install folder). Loads the dissector from this repository with
`-X lua_script:` inside a throwaway WIRESHARK_CONFIG_DIR, so installed
plugins and user preferences don't interfere.
"""

import json
import os
import shutil
import sys
import tempfile
import unittest

from helpers import FIXTURES, TESTS_DIR, TOOL_DIR, run_backend

sys.path.insert(0, os.path.join(TESTS_DIR, 'live'))
import cases as live_cases  # noqa: E402
import live_test  # noqa: E402

TSHARK = live_test.find_tshark()


@unittest.skipIf(TSHARK is None, 'tshark not found')
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

    def test_generated_packet_verdicts(self):
        """gen-packets captures: every frame gets the verdict its manifest expects."""

        for mode in ('ports', 'protocol'):
            for root in (os.path.join(os.path.dirname(FIXTURES), 'rules'), FIXTURES,
                         os.path.join(TOOL_DIR, 'examples', 'stress', 'protos')):
                with self.subTest(mode=mode, root=root):
                    tmp = tempfile.mkdtemp(prefix='nanopb_ws_tshark_gen_')
                    try:
                        self.check_generated(root, tmp, mode)
                    finally:
                        shutil.rmtree(tmp, ignore_errors=True)

    def check_generated(self, root, tmp, mode):
        plugins = os.path.join(tmp, 'plugins')
        status, result, err = run_backend('gen-packets', '--mode', mode, '--protos-root', root, '--out', tmp,
                                          '--plugins-dir', plugins)
        self.assertEqual(status, 0, err)
        with open(result['manifest']) as handle:
            manifest = json.load(handle)
        env = dict(os.environ, WIRESHARK_CONFIG_DIR=os.path.join(tmp, 'config'),
                   NANOPB_WS_SCHEMA=os.path.join(plugins, 'nanopb', 'schema.luadata'),
                   NANOPB_WS_PORTS=os.path.join(tmp, 'no_ports.luadata'))
        os.makedirs(env['WIRESHARK_CONFIG_DIR'])
        base = [TSHARK, '-X', 'lua_script:' + os.path.join(TOOL_DIR, 'nanopb_any_dissector.lua'),
                '-o', 'nanopb.port_map:' + manifest['port_map'], '-r', result['pcap']]
        # Protocol mode: a real Decode As of each protocol's port.
        for entry in manifest['protocol_ports']:
            transport, rest = entry.split(':')
            port, name = rest.split('=')
            base += ['-d', '%s.port==%s,%s' % (transport, port, name.lower())]
        status, out = live_test.run(base + ['-T', 'fields', '-e', 'frame.number', '-e', 'nanopb.validation',
                                            '-e', 'nanopb.validation.field', '-E', 'occurrence=a',
                                            '-E', 'aggregator=|'], env)
        self.assertEqual(status, 0, out)
        got = {}
        for line in out.splitlines():
            parts = line.split('\t') + ['', '']
            if parts[0].isdigit():
                got[int(parts[0])] = (parts[1], parts[2])
        for entry in manifest['packets']:
            verdict, fields = got.get(entry['frame'], ('', ''))
            self.assertEqual(verdict, entry['expect'], '%s frame %d %s' % (root, entry['frame'], entry))
            if entry['violate']:
                self.assertIn(entry['violate']['field'], fields, '%s frame %d %s' % (root, entry['frame'], entry))
        if mode == 'protocol':
            status, out = live_test.run(base + ['-T', 'fields', '-e', '_ws.col.Protocol'], env)
            self.assertEqual(status, 0, out)
            names = set(e.split('=')[1].upper() for e in manifest['protocol_ports'])
            self.assertEqual(set(out.split()), names, out)
        # The display filter selects exactly the dropped packets.
        status, out = live_test.run(base + ['-Y', 'nanopb.validation == "dropped"', '-T', 'fields',
                                            '-e', 'frame.number'], env)
        dropped = set(int(x) for x in out.split() if x.isdigit())
        self.assertEqual(dropped, set(e['frame'] for e in manifest['packets'] if e['expect'] == 'dropped'))


if __name__ == '__main__':
    unittest.main()
