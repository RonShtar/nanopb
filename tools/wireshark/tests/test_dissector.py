"""Runs the Wireshark Lua plugins against a mock Wireshark API (wireshark_mock.lua).

Needs ``pip install lupa`` (Lua 5.4 inside Python); skipped otherwise.
This checks decoding logic and the studio -> backend flow; it does not
replace a check in a real Wireshark (see tests/live).
"""

import json
import os
import re
import shutil
import struct
import sys
import tempfile
import unittest

from helpers import (FIXTURES, REPO_ROOT, TESTS_DIR, TOOL_DIR, any_of, f_bytes, f_fixed32, f_fixed64, f_sint,
                     f_varint, run_backend, varint)

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


RULES_PROTOS = os.path.join(os.path.dirname(FIXTURES), 'rules')
RULES_PORT = 5300
NOW = 1700000000


def inner(code=1, tag='t-a'):
    return f_varint(1, code) + f_bytes(2, tag)


def envelope(body=b'', inner_msg=None, at=1000, extra=b''):
    """A valid rules.Envelope (small=1 in the oneof) unless parts are replaced."""

    data = f_bytes(1, inner() if inner_msg is None else inner_msg) if inner_msg is not False else b''
    data += body if body else f_varint(6, 1)
    data += extra
    if at is not None:
        data += f_bytes(8, f_varint(1, at))
    return data


VALID_NUMBERS = f_fixed64(7, 'Q', 10)
VALID_STRINGS = (f_bytes(1, 'ab') + f_bytes(2, 'a@b.c') + f_bytes(7, 'a') + f_bytes(8, 'ok!') + f_bytes(9, 'v1')
                 + f_bytes(10, b'\x01') + f_bytes(11, b'\xca\xfe') + f_bytes(12, b'\x01'))


class ValidationTests(LuaTestCase):
    """Dissector verdicts on the rules fixture, against the semantics of pb_validate."""

    def setUp(self):
        super(ValidationTests, self).setUp()
        status, _, err = run_backend('install-dissector', '--protos-root', RULES_PROTOS, '--plugins-dir', self.tmp,
                                     '--port-map', 'udp:%d=rules.Envelope' % RULES_PORT)
        self.assertEqual(status, 0, err)
        self.mock.now = NOW
        self.lua.execute('dofile("%s")' % lua_path(os.path.join(self.tmp, 'nanopb_any_dissector.lua')))
        self.proto = self.mock.protos['nanopb']

    def verdict(self, data):
        tree = self.mock.tree()
        pinfo = self.mock.pinfo(PORT_TYPE['udp'], RULES_PORT)
        self.proto.dissector(self.mock.tvb(data), pinfo, tree)
        text = self.mock.render(tree)
        problems = re.findall(r'^    (\S+): ([\w.]+) - ', text, re.M)
        return ('dropped' if 'Validation: DROPPED' in text else 'passed'), problems, text, pinfo.cols.info.value

    def assertPasses(self, data):
        verdict, problems, text, _ = self.verdict(data)
        self.assertEqual(verdict, 'passed', text)

    def assertDrops(self, data, path, rule):
        verdict, problems, text, _ = self.verdict(data)
        self.assertEqual(verdict, 'dropped', text)
        self.assertIn((path, rule), problems, text)

    def numbers(self, *fields):
        return envelope(body=f_bytes(3, VALID_NUMBERS + b''.join(fields)))

    def strings(self, *fields):
        return envelope(body=f_bytes(4, VALID_STRINGS + b''.join(fields)))

    def lists(self, *fields):
        return envelope(body=f_bytes(5, f_varint(1, 1) + b''.join(fields)))

    def test_valid_envelope_passes(self):
        verdict, _, text, info = self.verdict(envelope())
        self.assertEqual(verdict, 'passed', text)
        self.assertTrue(info.endswith('[PASSED]'), info)
        self.assertRegex(text, r'Validation: PASSED \(\d+ checks\)')

    def test_presence(self):
        self.assertDrops(envelope(inner_msg=False), 'inner', 'required')
        self.assertDrops(envelope(inner_msg=inner(code=0)), 'inner.code', 'uint32.gte')
        # optional field: absent is fine, present is checked
        self.assertPasses(envelope())
        self.assertDrops(envelope(extra=f_varint(2, 4)), 'opt', 'uint32.gte')
        self.assertPasses(envelope(extra=f_varint(2, 5)))
        # oneof arm is checked only when selected
        self.assertDrops(envelope(body=f_varint(6, 4)), 'small', 'uint32.lte')

    def test_implicit_fields_are_checked_at_their_default(self):
        # x64 (fixed64 gte 10) is absent, so it is 0 and fails, as in the C struct.
        self.assertDrops(envelope(body=f_bytes(3, b'')), 'numbers.x64', 'fixed64.gte')
        self.assertPasses(self.numbers())

    def test_numbers(self):
        self.assertDrops(self.numbers(f_varint(1, -10)), 'numbers.i32', 'int32.gt')
        self.assertDrops(self.numbers(f_sint(2, 13)), 'numbers.s32', 'sint32.not_in')
        self.assertDrops(self.numbers(f_varint(3, 3)), 'numbers.u32', 'uint32.in')
        self.assertPasses(self.numbers(f_varint(4, -5000000000)))
        self.assertDrops(self.numbers(f_varint(4, -5000000001)), 'numbers.i64', 'int64.gte')
        self.assertPasses(self.numbers(f_varint(5, 9000000000000000000)))
        self.assertDrops(self.numbers(f_varint(5, (1 << 64) - 1)), 'numbers.u64', 'uint64.lte')
        self.assertDrops(self.numbers(f_sint(6, -1)), 'numbers.s64', 'sint64.not_in')
        self.assertPasses(self.numbers(f_sint(6, -(1 << 63))))
        self.assertDrops(self.numbers(f_fixed32(8, 'i', 1)), 'numbers.sf32', 'sfixed32.lte')
        self.assertDrops(self.numbers(f_fixed64(10, 'd', -1.5)), 'numbers.dbl', 'double.gt')
        self.assertDrops(self.numbers(f_varint(11, 1)), 'numbers.flag', 'bool.const')
        self.assertDrops(self.numbers(f_varint(12, 2)), 'numbers.level', 'enum.not_in')
        self.assertDrops(self.numbers(f_varint(12, 5)), 'numbers.level', 'enum.defined_only')

    def test_float_constants_are_float32(self):
        # C compares a float with (float)0.1, so 0.1f itself passes.
        self.assertPasses(self.numbers(f_fixed32(9, 'f', 0.1)))
        self.assertDrops(self.numbers(f_fixed32(9, 'f', 0.10001)), 'numbers.ratio', 'float.lte')
        self.assertPasses(self.lists(f_bytes(6, struct.pack('<ff', 0.1, -3.0))))
        self.assertDrops(self.lists(f_bytes(6, struct.pack('<ff', 0.0, 0.2))), 'lists.temps[1]', 'float.lte')

    def test_strings(self):
        self.assertPasses(self.strings())
        self.assertDrops(envelope(body=f_bytes(4, b'')), 'strings.name', 'string.min_len')
        self.assertDrops(self.strings(f_bytes(1, 'abcdefghijk')), 'strings.name', 'string.max_len')
        # C sees the string up to the first NUL: "ab" is short enough.
        self.assertPasses(self.strings(f_bytes(1, b'ab\x00cdefghijkl')))
        self.assertDrops(self.strings(f_bytes(2, 'a..b@c')), 'strings.email', 'string.email')
        self.assertPasses(self.strings(f_bytes(2, 'a@b')))
        self.assertDrops(self.strings(f_bytes(3, '-bad.example')), 'strings.host', 'string.hostname')
        self.assertPasses(self.strings(f_bytes(3, 'a-1.example')))
        self.assertDrops(self.strings(f_bytes(4, '1.2.3.256')), 'strings.ip4', 'string.ipv4')
        self.assertPasses(self.strings(f_bytes(5, '1::')))
        self.assertPasses(self.strings(f_bytes(5, '::ffff:1.2.3.4')))
        self.assertDrops(self.strings(f_bytes(5, '1:2:')), 'strings.ip6', 'string.ipv6')
        self.assertDrops(self.strings(f_bytes(5, '1::2::3')), 'strings.ip6', 'string.ipv6')
        self.assertPasses(self.strings(f_bytes(6, 'fe80::1')))
        self.assertDrops(self.strings(f_bytes(6, 'host')), 'strings.addr', 'string.ip')
        self.assertDrops(self.strings(f_bytes(7, 'd')), 'strings.code', 'string.in')
        self.assertDrops(self.strings(f_bytes(8, 'okay')), 'strings.note', 'string.suffix')
        self.assertDrops(self.strings(f_bytes(8, 'no!')), 'strings.note', 'string.contains')
        self.assertDrops(self.strings(f_bytes(8, 'ok\xe9!')), 'strings.note', 'string.ascii')
        self.assertDrops(self.strings(f_bytes(9, 'v2')), 'strings.version', 'string.const')

    def test_bytes(self):
        self.assertDrops(self.strings(f_bytes(10, b'\x02')), 'strings.blob', 'bytes.prefix')
        self.assertDrops(self.strings(f_bytes(10, b'\x01\x00\x00\x00\x00')), 'strings.blob', 'bytes.max_len')
        # bytes keep embedded NULs
        self.assertPasses(self.strings(f_bytes(10, b'\x01\x00')))
        self.assertDrops(self.strings(f_bytes(11, b'\xca')), 'strings.magic', 'bytes.const')
        self.assertDrops(self.strings(f_bytes(12, b'\x03')), 'strings.kind', 'bytes.in')

    def test_repeated(self):
        self.assertDrops(envelope(body=f_bytes(5, b'')), 'lists.nums', 'repeated.min_items')
        self.assertDrops(self.lists(f_varint(1, 1)), 'lists.nums[1]', 'repeated.unique')
        self.assertDrops(self.lists(f_bytes(1, varint(2) + varint((1 << 64) - 1))), 'lists.nums[2]', 'int32.gte')
        self.assertDrops(self.lists(f_bytes(2, '')), 'lists.words[0]', 'string.min_len')
        self.assertDrops(self.lists(f_varint(3, 1), f_varint(3, 7)), 'lists.levels[1]', 'enum.defined_only')
        self.assertDrops(self.lists(f_bytes(5, inner()), f_bytes(5, inner(code=100))), 'lists.inners[1].code',
                         'uint32.lte')
        pairs = b''.join(f_bytes(4, f_bytes(1, k) + f_varint(2, 1)) for k in ('a', 'b', 'c'))
        self.assertDrops(self.lists(pairs), 'lists.counts', 'map.max_pairs')

    def test_any(self):
        self.assertPasses(envelope(extra=f_bytes(7, any_of('rules.Inner', inner()))))
        self.assertDrops(envelope(extra=f_bytes(7, any_of('rules.Numbers', b''))), 'extra', 'any.in')
        bad_payload = envelope(extra=f_bytes(7, any_of('rules.Inner', inner(code=0))))
        self.assertDrops(bad_payload, 'extra<rules.Inner>.code', 'uint32.gte')
        self.proto.pref_values['validate_any'] = False
        self.assertPasses(bad_payload)

    def test_timestamp_uses_capture_time(self):
        self.assertPasses(envelope(at=NOW - 1))
        self.assertDrops(envelope(at=NOW), 'at', 'timestamp.lt_now')

    def test_nanopb_decode_failures(self):
        self.assertDrops(self.strings(f_bytes(1, 'x' * 16)), 'strings.name', 'nanopb.max_size')
        five = b''.join(f_varint(1, n) for n in (2, 3, 4, 5, 6))
        self.assertDrops(self.lists(five), 'lists.nums', 'nanopb.max_count')
        self.assertDrops(envelope(body=f_bytes(6, b'\x01')), 'small', 'decode.wire_type')
        self.assertDrops(self.numbers(f_varint(1, 1 << 40)), 'numbers.i32', 'decode.int_range')
        _, problems, text, info = self.verdict(envelope()[:-1])
        self.assertIn('[DROPPED decode.malformed', info)

    def test_validation_pref_off(self):
        self.proto.pref_values['validate'] = False
        _, _, text, info = self.verdict(envelope(body=f_varint(6, 4)))
        self.assertNotIn('Validation', text)
        self.assertNotIn('[', info)

    def test_info_column_and_fields(self):
        verdict, _, text, info = self.verdict(envelope(body=f_varint(6, 4)))
        self.assertEqual(info, 'nanopb rules.Envelope (%d bytes) [DROPPED uint32.lte small]'
                         % len(envelope(body=f_varint(6, 4))))
        self.assertIn('!nanopb.validation.violation: small: uint32.lte - must be <= 3 (got 4)', text)
        self.assertIn('Field: small', text)


class GeneratedPacketsTests(LuaTestCase):
    """gen-packets output, routed by port through the mock: verdicts match the manifest."""

    def test_verdicts_match_manifest(self):
        for root in (RULES_PROTOS, FIXTURES, os.path.join(TOOL_DIR, 'examples', 'stress', 'protos')):
            with self.subTest(root=root):
                self.check(root)

    def check(self, root):
        plugins = tempfile.mkdtemp(prefix='nanopb_ws_gen_', dir=self.tmp)
        status, result, err = run_backend('gen-packets', '--protos-root', root, '--out', plugins,
                                          '--plugins-dir', plugins)
        self.assertEqual(status, 0, err)
        with open(result['manifest']) as handle:
            manifest = json.load(handle)
        self.lua.execute('dofile("%s")' % lua_path(os.path.join(plugins, 'nanopb_any_dissector.lua')))
        proto = self.mock.protos['nanopb']
        for entry in manifest['packets']:
            tree = self.mock.tree()
            pinfo = self.mock.pinfo(PORT_TYPE[entry['transport']], entry['port'])
            proto.dissector(self.mock.tvb(bytes.fromhex(entry['hex'])), pinfo, tree)
            text = self.mock.render(tree)
            self.assertIn('Validation: %s' % entry['expect'].upper(), text, '%s\n%s' % (entry, text))
            if entry['violate']:
                self.assertRegex(text, r'\n    [^\n]*\b%s\b[^\n]* - ' % re.escape(entry['violate']['field']),
                                 '%s\n%s' % (entry, text))


class UnenforcedRulesTests(LuaTestCase):
    def test_not_checked_rules_never_drop(self):
        status, _, err = run_backend('install-dissector', '--protos-root',
                                     os.path.join(os.path.dirname(FIXTURES), 'rules_unenforced'),
                                     '--plugins-dir', self.tmp, '--port-map', 'udp:5400=unenforced.Form')
        self.assertEqual(status, 0, err)
        self.lua.execute('dofile("%s")' % lua_path(os.path.join(self.tmp, 'nanopb_any_dissector.lua')))
        proto = self.mock.protos['nanopb']
        tree = self.mock.tree()
        # name "AB" breaks the pattern but not min_len; no oneof arm and no name for "requires".
        proto.dissector(self.mock.tvb(f_bytes(1, 'AB')), self.mock.pinfo(PORT_TYPE['udp'], 5400), tree)
        text = self.mock.render(tree)
        self.assertIn('Validation: PASSED', text)
        for line in ('Not checked: unenforced.Form: message.requires', 'Not checked: name: string.pattern',
                     'Not checked: phone: oneof_required', 'Not checked: extra: map.no_sparse'):
            self.assertIn(line, text)


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

    def picker(self, menu, title, input_dir=FIXTURES):
        self.answer(title, input_dir, self.out)
        self.mock.menus[menu]()
        window = self.last_window()
        self.assertEqual(window.title, title + ': choose units')
        return window

    def test_menus_registered(self):
        names = set(self.mock.menus.keys())
        self.assertEqual(names, {'nanopb/Generate C (merged + validation)...',
                                 'nanopb/Generate test packets (passed + dropped)...',
                                 'nanopb/Install or update dissector...', 'nanopb/About'})

    def test_generate_c_through_backend(self):
        picker = self.picker('nanopb/Generate C (merged + validation)...', 'Generate C (merged + validation)')
        self.assertIn('[x] envelope', picker.text)
        self.assertIn('[x] telemetry', picker.text)
        picker.buttons['telemetry']()
        self.assertIn('[ ] telemetry', picker.text)
        picker.buttons['Generate']()
        window = self.last_window()
        self.assertTrue(window.text.startswith('OK'), window.text)
        self.assertIsNotNone(window.buttons['Open output folder'])
        self.assertEqual(os.listdir(self.out), ['envelope'])
        # Only the generated files: all protos of the unit merged, with validation.
        self.assertEqual(sorted(os.listdir(os.path.join(self.out, 'envelope'))), ['envelope.c', 'envelope.h'])
        with open(os.path.join(self.out, 'envelope', 'envelope.c')) as handle:
            self.assertIn('pb_validate_demo_envelope_Envelope', handle.read())
        with open(os.path.join(self.tmp, 'nanopb', 'studio_config.luadata')) as handle:
            self.assertIn(self.out.replace('\\', '\\\\'), handle.read())

    def test_unit_merged_into_another_starts_deselected(self):
        stress = os.path.join(TOOL_DIR, 'examples', 'stress', 'protos')
        picker = self.picker('nanopb/Generate C (merged + validation)...', 'Generate C (merged + validation)',
                             input_dir=stress)
        self.assertIn('[x] fleet', picker.text)
        self.assertIn('[ ] shared   (already merged into fleet)', picker.text)
        picker.buttons['Generate']()
        self.assertTrue(self.last_window().text.startswith('OK'), self.last_window().text)
        self.assertEqual(os.listdir(self.out), ['fleet'])

    def test_generate_with_nothing_selected(self):
        picker = self.picker('nanopb/Generate C (merged + validation)...', 'Generate C (merged + validation)')
        picker.buttons['Select none']()
        windows = len(self.mock.windows)
        picker.buttons['Generate']()
        self.assertEqual(len(self.mock.windows), windows)  # no result window
        self.assertIn('Select at least one unit.', picker.text)
        self.assertFalse(os.path.exists(self.out))

    def record_gui_calls(self):
        self.lua.execute('''
            gui_calls = {}
            local function record(...) gui_calls[#gui_calls + 1] = table.concat({ ... }, "|") end
            function open_capture_file(path, filter) record("open", path, filter) end
            function reload_lua_plugins() record("reload") end
            function set_filter(text) record("filter", text) end
            function apply_filter() record("apply") end
        ''')
        return self.lua.eval('gui_calls')

    def test_generate_test_packets_one_button(self):
        calls = self.record_gui_calls()
        title = 'Generate test packets'
        picker = self.picker('nanopb/Generate test packets (passed + dropped)...', title)
        picker.buttons['Generate']()
        window = self.last_window()
        self.assertTrue(window.text.startswith('OK'), window.text)
        self.assertRegex(window.text, r'\d+ packets: \d+ expected PASSED, \d+ expected DROPPED')
        pcap = os.path.join(self.out, 'nanopb_test_packets.pcapng')
        self.assertTrue(os.path.isfile(pcap))
        # The dissector and schema are refreshed next to the studio, the capture
        # is opened, then (schema changed) the plugins are reloaded.
        self.assertTrue(os.path.isfile(os.path.join(self.tmp, 'nanopb', 'schema.luadata')))
        self.assertEqual([calls[i] for i in range(1, len(calls) + 1)], ['open|%s|' % pcap, 'reload'])
        window.buttons['Show dropped only']()
        self.assertEqual(calls[len(calls)], 'apply')  # Lua tables are 1-based
        self.assertEqual(calls[len(calls) - 1], 'filter|nanopb.validation == "dropped"')
        self.assertIsNotNone(window.buttons['Open output folder'])
        # The ports gen-packets picked are kept for the dissector and Generate C.
        with open(os.path.join(self.tmp, 'nanopb', 'studio_config.luadata')) as handle:
            self.assertIn('udp:15000=demo.envelope.Envelope', handle.read())

        # Same protos again: nothing to reload.
        picker = self.picker('nanopb/Generate test packets (passed + dropped)...', title)
        before = len(calls)
        picker.buttons['Generate']()
        self.assertEqual([calls[i] for i in range(before + 1, len(calls) + 1)], ['open|%s|' % pcap])

    def test_install_dissector_next_to_studio(self):
        self.answer('Install / update dissector', FIXTURES, 'udp:5000=demo.envelope.Envelope')
        self.mock.menus['nanopb/Install or update dissector...']()
        window = self.last_window()
        self.assertTrue(window.text.startswith('OK'), window.text)
        self.assertIn('Ctrl+Shift+L', window.text)
        self.assertTrue(os.path.isfile(os.path.join(self.tmp, 'nanopb_any_dissector.lua')))
        self.assertTrue(os.path.isfile(os.path.join(self.tmp, 'nanopb', 'schema.luadata')))
        with open(os.path.join(self.tmp, 'nanopb', 'studio_config.luadata')) as handle:
            self.assertIn('udp:5000=demo.envelope.Envelope', handle.read())

    def test_backend_failure_is_reported(self):
        missing = os.path.join(self.tmp, 'nope')
        self.answer('Generate C (merged + validation)', missing, self.out)
        self.mock.menus['nanopb/Generate C (merged + validation)...']()
        window = self.last_window()
        self.assertTrue(window.text.startswith('FAILED'), window.text)
        self.assertIn('is not a directory', window.text)


if __name__ == '__main__':
    unittest.main()
