"""Runs the Wireshark Lua plugins against a mock Wireshark API (wireshark_mock.lua).

Needs ``pip install lupa`` (Lua 5.4 inside Python); skipped otherwise.
This checks decoding logic and the studio -> backend flow; it does not
replace a manual test in a real Wireshark.
"""

import os
import shutil
import struct
import sys
import tempfile
import unittest

from helpers import (FIXTURES, REPO_ROOT, TESTS_DIR, TOOL_DIR, any_of, f_bytes, f_fixed32,
                     f_fixed64, f_sint, f_varint, run_backend, varint)

try:
    import lupa.lua54 as lupa
except ImportError:  # pragma: no cover
    lupa = None

UDP, TCP = 3, 2


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
                                     '--port-map', 'udp:5000=demo.envelope.Envelope,tcp:7000=demo.telemetry.Telemetry')
        self.assertEqual(status, 0, err)
        self.lua.execute('dofile("%s")' % lua_path(os.path.join(self.tmp, 'nanopb_any_dissector.lua')))
        self.proto = self.mock.protos['nanopb']

    def dissect(self, data, port_type=UDP, port=5000):
        tvb = self.mock.tvb(data)
        tree = self.mock.tree()
        pinfo = self.mock.pinfo(port_type, port)
        consumed = self.proto.dissector(tvb, pinfo, tree)
        self.assertEqual(consumed, len(data))
        return self.mock.render(tree), pinfo

    def test_ports_registered(self):
        same = self.lua.eval('rawequal')
        self.assertTrue(same(self.mock.tables['udp.port'].entries[5000], self.proto))
        self.assertTrue(same(self.mock.tables['tcp.port'].entries[7000], self.proto))
        self.assertTrue(self.mock.tables['udp.port'].decode_as)

    def test_any_resolves_payload_type(self):
        ping = f_varint(1, 7)
        command = f_bytes(1, 'go') + f_varint(2, -5) + f_bytes(3, ping)
        envelope = (f_varint(1, 3) + f_bytes(2, any_of('demo.payloads.Command', command))
                    + f_bytes(3, f_varint(1, 9)))
        text, pinfo = self.dissect(envelope)
        self.assertIn('nanopb Protobuf: demo.envelope.Envelope', text)
        self.assertIn('version: 3', text)
        self.assertIn('body (2): google.protobuf.Any -> demo.payloads.Command', text)
        self.assertIn('Any type_url: type.googleapis.com/demo.payloads.Command', text)
        self.assertIn('value: Any -> demo.payloads.Command', text)
        self.assertIn('name: go', text)
        self.assertIn('arg: -5', text)
        self.assertIn('inner (3): demo.payloads.Ping', text)
        self.assertIn('id: 7', text)
        self.assertIn('last_ping (3): demo.payloads.Ping', text)
        self.assertIn('id: 9', text)
        self.assertNotIn('!', text)
        self.assertEqual(pinfo.cols.info.value, 'nanopb demo.envelope.Envelope (%d bytes)' % len(envelope))

    def test_nested_any_recursion(self):
        inner = f_varint(1, 1) + f_bytes(2, any_of('demo.payloads.Ping', f_varint(1, 42)))
        outer = f_varint(1, 2) + f_bytes(2, any_of('demo.envelope.Envelope', inner))
        text, _ = self.dissect(outer)
        self.assertIn('value: Any -> demo.envelope.Envelope', text)
        self.assertIn('value: Any -> demo.payloads.Ping', text)
        self.assertIn('id: 42', text)
        self.assertNotIn('!', text)

    def test_root_any_fallback_on_unmapped_port(self):
        data = any_of('demo.payloads.Ping', f_varint(1, 99))
        text, _ = self.dissect(data, UDP, 6000)
        self.assertIn('nanopb Protobuf: google.protobuf.Any', text)
        self.assertIn('id: 99', text)

    def test_default_message_pref(self):
        self.proto.pref_values['default_message'] = 'demo.payloads.Ping'
        text, _ = self.dissect(f_varint(1, 5), UDP, 6000)
        self.assertIn('nanopb Protobuf: demo.payloads.Ping', text)
        self.assertIn('id: 5', text)

    def test_unknown_any_type(self):
        envelope = f_bytes(2, any_of('other.Thing', b'\x08\x01'))
        text, _ = self.dissect(envelope)
        self.assertIn('type other.Thing not in schema', text)
        self.assertIn('!nanopb.any.unknown_type', text)

    def test_scalar_types_enum_packed(self):
        header = f_varint(1, 1) + f_fixed64(2, 'Q', 1234567890123) + f_bytes(3, 's1')
        reading = f_varint(1, 1) + f_fixed32(2, 'f', 21.5) + f_sint(3, -3)
        packed = varint(((1 << 64) - 1)) + varint(300)  # int32 -1 is a 10-byte varint
        telemetry = (f_bytes(1, header) + f_bytes(2, 'dev') + f_bytes(3, reading) + f_bytes(4, packed)
                     + f_bytes(5, b'\x01\x02') + f_fixed64(6, 'd', 0.25) + f_varint(7, 1))
        text, _ = self.dissect(telemetry, TCP, 7000)
        for expected in ('seq: 1', 'timestamp_us: 1234567890123', 'source: s1', 'device_name: dev',
                         'unit: UNIT_CELSIUS (1)', 'value: 21.5', 'offset: -3', 'raw (4): packed [2]',
                         'raw: -1', 'raw: 300', 'blob: 0102', 'ratio: 0.25', 'healthy: true'):
            self.assertIn(expected, text)
        self.assertNotIn('!', text)

    def test_unknown_fields_and_malformed(self):
        text, _ = self.dissect(f_varint(1, 1) + f_varint(15, 77) + f_bytes(14, f_varint(1, 2)))
        self.assertIn('field_15: 77', text)
        self.assertIn('field 14: 2 bytes', text)
        text, _ = self.dissect(f_varint(1, 1) + b'\x12\x10\x01')  # length beyond end
        self.assertIn('!nanopb.malformed: Length exceeds message', text)

    def test_typed_filter_fields(self):
        abbrs = set(f.abbr for f in self.proto.fields.values())
        for name in ('nanopb.demo.payloads.Ping.id', 'nanopb.demo.telemetry.Telemetry.device_name',
                     'nanopb.type_url', 'nanopb.message'):
            self.assertIn(name, abbrs)


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
