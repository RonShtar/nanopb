"""Runs the Wireshark Lua plugins against a mock Wireshark API (wireshark_mock.lua).

Needs ``pip install lupa`` (Lua 5.4 inside Python); skipped otherwise.
This checks decoding logic and the studio -> backend flow; it does not
replace a check in a real Wireshark (see tests/live).
"""

import os
import re
import shutil
import sys
import tempfile
import unittest

from helpers import FIXTURES, REPO_ROOT, TESTS_DIR, TOOL_DIR, f_bytes, f_varint, run_backend

sys.path.insert(0, os.path.join(TESTS_DIR, 'live'))
import cases as live_cases  # noqa: E402
import live_test  # noqa: E402

try:
    import lupa.lua54 as lupa
except ImportError:  # pragma: no cover
    lupa = None

PORT_TYPE = {'udp': 3, 'tcp': 2}


def lua_path(path):
    return path.replace('\\', '/')


@unittest.skipIf(lupa is None, 'lupa not installed')
class LuaTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='nanopb_ws_lua_')
        self.lua = lupa.LuaRuntime(unpack_returned_tuples=True)
        self.mock = self.lua.eval('dofile("%s")' % lua_path(os.path.join(TESTS_DIR, 'wireshark_mock.lua')))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)


class DissectorTests(LuaTestCase):
    def setUp(self):
        super(DissectorTests, self).setUp()
        status, _, err = run_backend('install-dissector', '--protos-root', FIXTURES, '--plugins-dir', self.tmp,
                                     '--port-map', live_cases.PORT_MAP)
        self.assertEqual(status, 0, err)
        self.lua.execute('dofile("%s")' % lua_path(os.path.join(self.tmp, 'nanopb_any_dissector.lua')))
        self.proto = self.mock.protos['nanopb']

    def route(self, transport, port, data, decode_as=False):
        """Dispatch like Wireshark: port table, then heuristics. Returns tree text or None."""

        tvb = self.mock.tvb(data)
        tree = self.mock.tree()
        pinfo = self.mock.pinfo(PORT_TYPE[transport], port)
        if decode_as or self.mock.tables[transport + '.port'].entries[port] is not None:
            self.assertEqual(self.proto.dissector(tvb, pinfo, tree), len(data))
        elif not self.mock.heuristics[transport](tvb, pinfo, tree):
            return None
        return self.mock.render(tree)

    def run_case(self, case):
        if case.how == 'decode_as':
            self.assertIsNone(self.route(case.transport, case.port, case.payload),
                              'decode-as case must not be claimed without Decode As')
            self.proto.pref_values['default_message'] = live_cases.DECODE_AS_MESSAGE
        text = self.route(case.transport, case.port, case.payload, decode_as=case.how == 'decode_as')
        self.assertIsNotNone(text, case.name)
        low = text.lower()
        for line in case.expect:
            self.assertIn(line.lower(), low, '%s\n%s' % (case.name, text))
        for line in case.experts:
            self.assertIn(line.lower(), low, '%s\n%s' % (case.name, text))
        if not case.experts:
            self.assertNotIn('!', text, '%s\n%s' % (case.name, text))
        return text

    def test_live_cases(self):
        for case in live_cases.all_cases(generated=3):
            with self.subTest(case=case.name):
                self.proto.pref_values['default_message'] = ''
                self.run_case(case)

    def test_filters_use_registered_fields(self):
        abbrs = set(f.abbr for f in self.proto.fields.values())
        abbrs |= set(e.abbr for e in self.proto.experts.values())
        for case in live_cases.CASES:
            for name in re.findall(r'nanopb[\w.]*', case.filter or ''):
                self.assertIn(name, abbrs, case.filter)

    def test_ports_registered(self):
        same = self.lua.eval('rawequal')
        self.assertTrue(same(self.mock.tables['udp.port'].entries[5000], self.proto))
        self.assertTrue(same(self.mock.tables['tcp.port'].entries[7000], self.proto))
        self.assertTrue(self.mock.tables['udp.port'].decode_as)

    def test_heuristic_rejects_other_traffic(self):
        for data in (b'GET / HTTP/1.1\r\n\r\n', f_varint(1, 5),
                     f_bytes(1, 'type.googleapis.com/no.Such') + f_bytes(2, b'\x08\x01'),
                     f_bytes(1, 'type.googleapis.com/demo.payloads.Ping') + f_bytes(2, b'\x0a\x05')):
            self.assertIsNone(self.route('udp', 6000, data), data)

    def test_heuristic_pref_off(self):
        self.proto.pref_values['heuristic'] = False
        case = [c for c in live_cases.CASES if c.how == 'heuristic'][0]
        self.assertIsNone(self.route(case.transport, case.port, case.payload))

    def test_unknown_fields(self):
        text = self.route('udp', 5000, f_varint(1, 1) + f_varint(15, 77) + f_bytes(14, f_varint(1, 2)))
        self.assertIn('field_15: 77', text)
        self.assertIn('field 14: 2 bytes', text)


class PcapSelfCheck(LuaTestCase):
    """The pcap written for Wireshark carries exactly the case payloads, and
    they dissect as expected when routed by their headers."""

    def test_pcap_round_trip(self):
        cases = live_cases.all_cases(generated=2)
        path = os.path.join(self.tmp, 'live.pcap')
        live_test.write_pcap(path, cases)
        packets = live_test.read_pcap(path)
        self.assertEqual(len(packets), len(cases))
        dissector = DissectorTests('route')
        dissector.lua, dissector.mock, dissector.tmp = self.lua, self.mock, self.tmp
        status, _, err = run_backend('install-dissector', '--protos-root', FIXTURES, '--plugins-dir', self.tmp,
                                     '--port-map', live_cases.PORT_MAP)
        self.assertEqual(status, 0, err)
        self.lua.execute('dofile("%s")' % lua_path(os.path.join(self.tmp, 'nanopb_any_dissector.lua')))
        dissector.proto = self.mock.protos['nanopb']
        for i, (case, (transport, sport, dport, payload, csum_ok)) in enumerate(zip(cases, packets)):
            with self.subTest(case=case.name):
                self.assertEqual((transport, dport, payload), (case.transport, case.port, case.payload))
                self.assertEqual(sport, live_test.SRC_PORT_BASE + i)
                self.assertTrue(csum_ok)
                dissector.proto.pref_values['default_message'] = ''
                dissector.run_case(case)

    def test_checklist_lists_every_case(self):
        cases = live_cases.all_cases(generated=1)
        text = live_test.checklist_markdown(cases)
        for i, case in enumerate(cases, 1):
            self.assertIn('### Packet %d: %s' % (i, case.name), text)


class StudioTests(LuaTestCase):
    def setUp(self):
        super(StudioTests, self).setUp()
        shutil.copy(os.path.join(TOOL_DIR, 'nanopb_studio.lua'), self.tmp)
        os.makedirs(os.path.join(self.tmp, 'nanopb'))
        self.out = os.path.join(self.tmp, 'out dir')  # space on purpose: exercises quoting
        with open(os.path.join(self.tmp, 'nanopb', 'studio_config.luadata'), 'w') as handle:
            handle.write('return { python = %r, nanopb_root = %r, protos_root = %r, output_dir = %r }\n'
                         % (sys.executable, REPO_ROOT, FIXTURES, self.out))
        self.lua.execute('dofile("%s")' % lua_path(os.path.join(self.tmp, 'nanopb_studio.lua')))

    def answer(self, title, *values):
        self.mock.dialog_answers[title] = self.lua.table(*values)

    def last_window(self):
        windows = self.mock.windows
        return windows[len(windows)]

    def test_menus_registered(self):
        names = set(self.mock.menus.keys())
        self.assertEqual(len(names), 6)
        self.assertIn('nanopb/Generate C (merged + validation)...', names)

    def test_generate_c_through_backend(self):
        self.answer('Generate C (merged, with validation)', 'envelope', 'n', 'y')
        self.mock.menus['nanopb/Generate C (merged + validation)...']()
        window = self.last_window()
        self.assertTrue(window.text.startswith('OK'), window.text)
        self.assertTrue(os.path.isfile(os.path.join(self.out, 'envelope', 'envelope.c')))
        self.assertIsNotNone(window.buttons['Open output folder'])

    def test_generate_data_through_backend(self):
        self.answer('Generate raw data', 'envelope', 'Ping', 'bin,hex', '2', '7', 'n', '', '')
        self.mock.menus['nanopb/Generate raw data...']()
        window = self.last_window()
        self.assertTrue(window.text.startswith('OK'), window.text)
        self.assertEqual(sorted(os.listdir(os.path.join(self.out, 'envelope', 'data'))),
                         ['demo_payloads_Ping_0.bin', 'demo_payloads_Ping_0.hex', 'demo_payloads_Ping_0.txt',
                          'demo_payloads_Ping_1.bin', 'demo_payloads_Ping_1.hex', 'demo_payloads_Ping_1.txt'])

    def test_install_dissector_next_to_studio(self):
        self.answer('Install / update dissector', 'udp:5000=demo.envelope.Envelope')
        self.mock.menus['nanopb/Install or update dissector...']()
        window = self.last_window()
        self.assertTrue(window.text.startswith('OK'), window.text)
        self.assertIn('Ctrl+Shift+L', window.text)
        self.assertTrue(os.path.isfile(os.path.join(self.tmp, 'nanopb_any_dissector.lua')))
        self.assertTrue(os.path.isfile(os.path.join(self.tmp, 'nanopb', 'schema.luadata')))
        with open(os.path.join(self.tmp, 'nanopb', 'studio_config.luadata')) as handle:
            self.assertIn('udp:5000=demo.envelope.Envelope', handle.read())

    def test_backend_failure_is_reported(self):
        self.answer('Generate C (merged, with validation)', 'nope', 'n', 'y')
        self.mock.menus['nanopb/Generate C (merged + validation)...']()
        window = self.last_window()
        self.assertTrue(window.text.startswith('FAILED'), window.text)
        self.assertIn('unknown unit(s) nope', window.text)


if __name__ == '__main__':
    unittest.main()
