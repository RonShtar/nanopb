"""Tests for tools/wireshark/backend/nanopb_wireshark.py.

Run: python -m unittest discover -s tools/wireshark/tests -v
Needs: protobuf, grpcio-tools (same as the nanopb generator).
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

from helpers import FIXTURES, TOOL_DIR, f_bytes, f_varint, run_backend

STRESS_PROTOS = os.path.join(TOOL_DIR, 'examples', 'stress', 'protos')
RULES_PROTOS = os.path.join(os.path.dirname(FIXTURES), 'rules')
UNENFORCED_PROTOS = os.path.join(os.path.dirname(FIXTURES), 'rules_unenforced')
STRESS_PORTS = 'udp:5100=fleet.envelope.Envelope,tcp:5101=fleet.telemetry.Frame,udp:5102=fleet.status.Status'


def unwrap_any(data):
    """The value bytes of an encoded google.protobuf.Any."""

    pos, value = 0, b''
    while pos < len(data):
        key = data[pos]
        pos += 1
        length, shift = 0, 0
        while True:
            b = data[pos]
            pos += 1
            length |= (b & 0x7f) << shift
            shift += 7
            if b < 0x80:
                break
        if key == 0x12:
            value = data[pos:pos + length]
        pos += length
    return value


def find_cc():
    """A C compiler command, or None (gcc/clang/cc on PATH, CC, or pip ziglang)."""

    if os.environ.get('CC'):
        return os.environ['CC'].split()
    for name in ('gcc', 'clang', 'cc'):
        if shutil.which(name):
            return [name]
    try:
        import ziglang  # noqa: F401
        return [sys.executable, '-m', 'ziglang', 'cc']
    except ImportError:
        return None


class BackendTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='nanopb_ws_test_')

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_units(self):
        status, result, _ = run_backend('units', '--protos-root', FIXTURES)
        self.assertEqual(status, 0)
        units = dict((u['unit'], u) for u in result['units'])
        self.assertEqual(sorted(units), ['envelope', 'telemetry'])
        self.assertIn('demo.envelope.Envelope', units['envelope']['messages'])
        self.assertEqual(units['envelope']['dependencies'], ['google/protobuf/any.proto'])
        self.assertIn('demo.common.Header', units['telemetry']['messages'])

    def read(self, *path):
        with open(os.path.join(self.tmp, *path)) as handle:
            return handle.read()

    def test_gen_c_merges_messages_and_validators_per_unit(self):
        status, result, err = run_backend('gen-c', '--protos-root', FIXTURES, '--out', self.tmp)
        self.assertEqual(status, 0, err)
        for unit in ('envelope', 'telemetry'):
            self.assertEqual(sorted(os.listdir(os.path.join(self.tmp, unit))),
                             [unit + '.pb.c', unit + '.pb.h', unit + '_validate.c', unit + '_validate.h'])
            pb_h, pb_c = self.read(unit, unit + '.pb.h'), self.read(unit, unit + '.pb.c')
            validate_h, validate_c = self.read(unit, unit + '_validate.h'), self.read(unit, unit + '_validate.c')

            def quoted(text):
                return re.findall(r'#include\s+"([^"]+)"', text)

            # Only the merged headers are included with quotes; the filter
            # core in .pb.c calls the validators.
            self.assertEqual(quoted(pb_h), [])
            self.assertEqual(quoted(pb_c), [unit + '.pb.h', unit + '_validate.h'])
            self.assertEqual(quoted(validate_h), [unit + '.pb.h'])
            self.assertEqual(quoted(validate_c), [unit + '_validate.h'])
            for header in (pb_h, validate_h):
                self.assertEqual(len(re.findall(r'^\s*#\s*if', header, re.M)),
                                 len(re.findall(r'^\s*#\s*endif', header, re.M)))
            self.assertIn('<pb_validate.h>', validate_h)
            self.assertNotIn('pb_validate', pb_h)
            self.assertNotIn('PB_BIND', validate_c)
            self.assertIn('_filter_core(', pb_c)
            self.assertNotIn('_filter_core(', validate_c)

        header = self.read('envelope', 'envelope.pb.h')
        # Dependency (Any) comes before its user, and storage is static.
        self.assertLess(header.index('} google_protobuf_Any;'), header.index('} demo_envelope_Envelope;'))
        self.assertNotIn('pb_callback_t', header)
        self.assertIn('demo_envelope_Envelope_size', header)
        for symbol in ('PB_BIND(demo_envelope_Envelope', 'PB_BIND(google_protobuf_Any'):
            self.assertIn(symbol, self.read('envelope', 'envelope.pb.c'))
        self.assertIn('bool pb_validate_demo_envelope_Envelope(', self.read('envelope', 'envelope_validate.c'))

    def schema_messages(self, root):
        from nanopb_wireshark import DEFAULT_NANOPB_ROOT, setup_nanopb, write_schema
        setup_nanopb(DEFAULT_NANOPB_ROOT)
        return write_schema(root, [], os.path.join(self.tmp, 'schema.luadata'))

    def test_schema_exports_rules(self):
        from nanopb_wireshark import int64_key
        messages = self.schema_messages(RULES_PROTOS)

        def field(msg, name):
            return next(f for f in messages['rules.' + msg]['fields'].values() if f['name'] == name)

        def rules(msg, name):
            return dict((r['id'], r) for r in field(msg, name)['rules'])

        self.assertEqual(rules('Numbers', 'i64')['int64.gte']['key'], int64_key(-5000000000, True))
        self.assertEqual(rules('Numbers', 'u64')['uint64.lte']['key'], '7ce66c50e2840000')
        self.assertEqual(rules('Numbers', 's64')['sint64.not_in']['keys'], ['7fffffffffffffff'])
        # float constants are float32 values, as C compares them.
        self.assertEqual(rules('Numbers', 'ratio')['float.lte']['v'], 0.10000000149011612)
        self.assertEqual(rules('Numbers', 'flag')['bool.const']['v'], False)
        self.assertEqual(rules('Strings', 'magic')['bytes.const']['v'], b'\xca\xfe')
        self.assertEqual(rules('Lists', 'nums')['repeated.items']['items'],
                         [{'id': 'int32.gte', 'kind': 'GTE', 'v': 0}])
        self.assertEqual(rules('Lists', 'nums')['repeated.max_items']['v'], 4)

        self.assertEqual(field('Numbers', 'i32')['presence'], 'implicit')
        self.assertEqual(field('Envelope', 'opt')['presence'], 'explicit')
        self.assertEqual(field('Envelope', 'inner')['presence'], 'explicit')
        self.assertEqual((field('Envelope', 'small')['presence'], field('Envelope', 'small')['oneof']),
                         ('oneof', 'body'))
        self.assertEqual((field('Lists', 'nums')['presence'], field('Lists', 'nums')['max_count']),
                         ('repeated', 4))
        self.assertEqual(field('Strings', 'name')['max_size'], 15)  # max_size 16 includes the NUL
        self.assertEqual(field('Strings', 'name')['storage'], 'static')

        with open(os.path.join(self.tmp, 'schema.luadata')) as handle:
            text = handle.read()
        self.assertIn('v = "\\202\\254"', text)  # 0xca 0xfe as Lua decimal escapes
        self.assertIn('key = "7ce66c50e2840000"', text)

    def test_schema_unsupported_rules(self):
        messages = self.schema_messages(UNENFORCED_PROTOS)
        form = messages['unenforced.Form']
        by_name = dict((f['name'], f) for f in form['fields'].values())
        name_rules = [(r['id'], r['kind']) for r in by_name['name']['rules']]
        # pattern is not checked, min_len on the same field still is.
        self.assertEqual(sorted(name_rules), [('string.min_len', 'MIN_LEN'), ('string.pattern', 'UNSUPPORTED')])
        self.assertEqual([(r['id'], r['kind']) for r in by_name['phone']['rules']],
                         [('oneof_required', 'UNSUPPORTED')])
        self.assertEqual([(r['id'], r['kind']) for r in by_name['extra']['rules']],
                         [('map.no_sparse', 'UNSUPPORTED')])
        self.assertEqual(form['message_rules'], [{'id': 'message.requires', 'kind': 'UNSUPPORTED',
                                                  'fields': ['name']}])

    def gen_packets(self, root, *extra):
        out = os.path.join(self.tmp, 'packets')
        status, result, err = run_backend('gen-packets', '--protos-root', root, '--out', out,
                                          '--plugins-dir', os.path.join(self.tmp, 'plugins'), *extra)
        self.assertEqual(status, 0, err)
        with open(result['manifest']) as handle:
            return result, json.load(handle)

    def test_gen_packets_capture_and_manifest(self):
        from nanopb_wireshark import read_capture
        result, manifest = self.gen_packets(FIXTURES)
        self.assertTrue(result['pcap'].endswith('.pcapng'))
        self.assertGreater(result['passed'], 0)
        self.assertGreater(result['dropped'], 0)
        self.assertEqual(result['passed'] + result['dropped'], len(manifest['packets']))
        # roots on their own port, everything else as Any on the (explicitly mapped) Any port
        self.assertIn('udp:15000=demo.envelope.Envelope', manifest['port_map'])
        self.assertIn('udp:15999=google.protobuf.Any', manifest['port_map'])
        packets = read_capture(result['pcap'])
        self.assertEqual(len(packets), len(manifest['packets']))
        for pkt, entry in zip(packets, manifest['packets']):
            self.assertEqual(pkt.payload.hex(), entry['hex'])
            self.assertEqual(pkt.port, entry['port'])
            self.assertTrue(pkt.comment.startswith('expect=%s msg=%s' % (entry['expect'].upper(), entry['message'])))
            if entry['expect'] == 'dropped':
                self.assertIn('field=%s rule=%s' % (entry['violate']['field'], entry['violate']['rule']), pkt.comment)
        wrapped = [e for e in manifest['packets'] if e['any_wrapped']]
        self.assertTrue(wrapped and all(e['port'] == 15999 for e in wrapped))
        self.assertTrue(os.path.isfile(os.path.join(self.tmp, 'plugins', 'nanopb', 'schema.luadata')))

    def test_gen_packets_reports_schema_changes(self):
        first, _ = self.gen_packets(FIXTURES)
        second, _ = self.gen_packets(FIXTURES)
        self.assertTrue(first['schema_changed'])
        self.assertFalse(second['schema_changed'])

    def test_gen_packets_pcap_format_and_no_install(self):
        from nanopb_wireshark import read_capture
        out = os.path.join(self.tmp, 'packets')
        status, result, err = run_backend('gen-packets', '--protos-root', FIXTURES, '--unit', 'telemetry',
                                          '--out', out, '--no-install', '--format', 'pcap', '--valid', '1')
        self.assertEqual(status, 0, err)
        self.assertTrue(result['pcap'].endswith('.pcap'))
        self.assertEqual(len(read_capture(result['pcap'])), result['passed'] + result['dropped'])
        self.assertNotIn('installed', result)

    @unittest.skipIf(find_cc() is None, 'no C compiler (gcc/clang/cc, CC, or pip install ziglang)')
    def test_gen_packets_verdicts_match_c_validator(self):
        """Every expected verdict is what pb_decode + pb_validate in C decide."""

        for root in (RULES_PROTOS, FIXTURES, STRESS_PROTOS):
            with self.subTest(root=os.path.basename(os.path.dirname(root)) + '/' + os.path.basename(root)):
                shutil.rmtree(os.path.join(self.tmp, 'packets'), ignore_errors=True)
                _, manifest = self.gen_packets(root)
                self.check_with_c(root, manifest)

    def check_with_c(self, root, manifest):
        from nanopb_wireshark import c_identifier
        by_unit = {}
        for entry in manifest['packets']:
            by_unit.setdefault(entry['unit'], []).append(entry)
        for unit, entries in by_unit.items():
            out = os.path.join(self.tmp, 'c_' + unit)
            status, result, err = run_backend('gen-c', '--protos-root', root, '--unit', unit, '--out', out,
                                              '--no-filter', '--with-runtime')
            self.assertEqual(status, 0, err)
            unit_dir = os.path.join(out, unit)
            with open(os.path.join(unit_dir, unit + '_validate.h')) as handle:
                header = handle.read()
            lines = ['#include <stdio.h>', '#include <string.h>', '#include <pb_decode.h>',
                     '#include "%s_validate.h"' % unit, '']
            checks = []
            for entry in entries:
                data = bytes.fromhex(entry['hex'])
                msg = entry['message']
                if entry['any_wrapped']:
                    data = unwrap_any(data)
                ctype = c_identifier(msg.replace('.', '_'))
                validate = ('pb_validate_%s(&m, &v)' % ctype) if ('bool pb_validate_%s(' % ctype) in header else 'true'
                name = 'frame_%d' % entry['frame']
                lines += ['static const pb_byte_t %s_data[] = {%s};' % (name, ', '.join(str(b) for b in data) or '0'),
                          'static int %s(void) {' % name,
                          '    static %s m;' % ctype,
                          '    pb_violations_t v;',
                          '    pb_istream_t s = pb_istream_from_buffer(%s_data, %d);' % (name, len(data)),
                          '    memset(&m, 0, sizeof(m));',
                          '    if (!pb_decode(&s, %s_fields, &m)) return 0;' % ctype,
                          '    pb_violations_init(&v);',
                          '    return %s;' % validate, '}']
                checks.append('    printf("%%d %%d\\n", %d, %s());' % (entry['frame'], name))
            lines += ['int main(void) {'] + checks + ['    return 0;', '}', '']
            main = os.path.join(unit_dir, 'main_check.c')
            with open(main, 'w') as handle:
                handle.write('\n'.join(lines))
            exe = os.path.join(unit_dir, 'check.exe')
            sources = [os.path.join(unit_dir, f) for f in os.listdir(unit_dir) if f.endswith('.c')]
            # Built with the smallest validation buffers gen-c recommends: they
            # must not change any verdict.
            defines = ['-D%s=%d' % kv for kv in sorted(result['units'][0]['recommended_defines'].items())]
            build = subprocess.run(find_cc() + ['-std=c99', '-I', unit_dir] + defines + ['-o', exe] + sources,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
            self.assertEqual(build.returncode, 0, build.stdout[-3000:])
            run = subprocess.run([exe], stdout=subprocess.PIPE, universal_newlines=True)
            verdicts = dict((int(a), b == '1') for a, b in (line.split() for line in run.stdout.splitlines()))
            for entry in entries:
                self.assertEqual('passed' if verdicts[entry['frame']] else 'dropped', entry['expect'],
                                 '%s frame %d %s %s' % (unit, entry['frame'], entry['message'], entry['violate']))

    def test_gen_c_exports_packet_filters(self):
        status, result, err = run_backend('gen-c', '--protos-root', FIXTURES, '--out', self.tmp)
        self.assertEqual(status, 0, err)
        units = dict((u['unit'], u) for u in result['units'])
        # No port map: the roots no other message of the unit refers to.
        self.assertEqual(units['envelope']['filters'], ['demo_envelope_Envelope_filter_udp'])
        self.assertEqual(units['envelope']['filter_entrypoints'],
                         {'from': 'auto', 'modes': {'demo.envelope.Envelope': 'auto'}})
        self.assertEqual(units['telemetry']['filters'], ['demo_telemetry_Telemetry_filter_udp'])
        self.assertIn('int demo_envelope_Envelope_filter_tcp(void *ctx, const uint8_t *packet, '
                      'size_t packet_size, bool is_to_server);', self.read('envelope', 'envelope.pb.h'))
        self.assertIn('static int demo_envelope_Envelope_filter_core(', self.read('envelope', 'envelope.pb.c'))

    def test_gen_c_filters_from_port_map(self):
        status, result, err = run_backend('gen-c', '--protos-root', STRESS_PROTOS, '--unit', 'fleet',
                                          '--out', self.tmp, '--port-map', STRESS_PORTS)
        self.assertEqual(status, 0, err)
        unit = result['units'][0]
        self.assertEqual(sorted(unit['filters']), ['fleet_envelope_Envelope_filter_udp',
                                                   'fleet_status_Status_filter_udp',
                                                   'fleet_telemetry_Frame_filter_udp'])
        # Envelope (Any + oneof) and Frame (two Any) are ambiguous for dispatch,
        # so they fall back to decoding and validating the entrypoint itself.
        self.assertEqual(unit['filter_entrypoints'],
                         {'from': 'port map', 'modes': {'fleet.envelope.Envelope': 'single',
                                                        'fleet.telemetry.Frame': 'single',
                                                        'fleet.status.Status': 'auto'}})
        self.assertNotIn('filter_errors', unit)
        # A path is a field name plus an array index ("readings[65535]").
        self.assertEqual(unit['recommended_defines'], {'PB_VALIDATE_MAX_PATH_DEPTH': 2,
                                                       'PB_VALIDATE_MAX_PATH_LENGTH': 19})
        self.assertIn('-DPB_VALIDATE_MAX_PATH_DEPTH=2 -DPB_VALIDATE_MAX_PATH_LENGTH=19', result['summary'])
        self.assertIn('fleet.pb.h, fleet.pb.c, fleet_validate.h, fleet_validate.c', result['summary'])

    def test_gen_c_no_filter(self):
        status, result, err = run_backend('gen-c', '--protos-root', FIXTURES, '--unit', 'envelope',
                                          '--out', self.tmp, '--no-filter')
        self.assertEqual(status, 0, err)
        self.assertEqual(result['units'][0]['filters'], [])

    @unittest.skipIf(find_cc() is None, 'no C compiler (gcc/clang/cc, CC, or pip install ziglang)')
    def test_gen_c_output_builds_and_filters(self):
        status, result, err = run_backend('gen-c', '--protos-root', FIXTURES, '--unit', 'telemetry',
                                          '--out', self.tmp, '--with-runtime')
        self.assertEqual(status, 0, err)
        unit_dir = os.path.join(self.tmp, 'telemetry')
        # device_name has min_len 1: without it the packet is rejected.
        good = f_bytes(1, f_varint(1, 7)) + f_bytes(2, 'dev-1')
        bad = f_bytes(1, f_varint(1, 7)) + f_varint(7, 1)
        main = os.path.join(unit_dir, 'main_check.c')
        with open(main, 'w') as handle:
            handle.write('\n'.join([
                '#include <stdio.h>',
                '#include "telemetry.pb.h"',
                'static const uint8_t good[] = {%s};' % ', '.join(str(b) for b in good),
                'static const uint8_t bad[] = {%s};' % ', '.join(str(b) for b in bad),
                'int main(void) {',
                '    printf("%d %d\\n", demo_telemetry_Telemetry_filter_udp(NULL, good, sizeof(good)),',
                '           demo_telemetry_Telemetry_filter_udp(NULL, bad, sizeof(bad)));',
                '    return 0;',
                '}', '']))
        exe = os.path.join(unit_dir, 'check.exe')
        sources = [os.path.join(unit_dir, f) for f in os.listdir(unit_dir) if f.endswith('.c')]
        build = subprocess.run(find_cc() + ['-std=c99', '-Wall', '-Werror', '-I', unit_dir, '-o', exe] + sources,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
        self.assertEqual(build.returncode, 0, build.stdout)
        run = subprocess.run([exe], stdout=subprocess.PIPE, universal_newlines=True)
        self.assertEqual(run.stdout.split(), ['0', '-1'])

    def test_gen_c_with_runtime_copies_it_as_separate_files(self):
        status, result, err = run_backend('gen-c', '--protos-root', FIXTURES, '--unit', 'telemetry',
                                          '--out', self.tmp, '--with-runtime')
        self.assertEqual(status, 0, err)
        files = set(os.listdir(os.path.join(self.tmp, 'telemetry')))
        self.assertEqual(files, {'telemetry.pb.c', 'telemetry.pb.h', 'telemetry_validate.c', 'telemetry_validate.h',
                                 'pb.h', 'pb_common.h', 'pb_common.c',
                                 'pb_encode.h', 'pb_encode.c', 'pb_decode.h', 'pb_decode.c',
                                 'pb_validate.h', 'pb_validate.c', 'pb_filter_macros.h'})

    def test_gen_c_writes_only_generated_files_by_default(self):
        status, result, err = run_backend('gen-c', '--protos-root', FIXTURES, '--unit', 'telemetry',
                                          '--out', self.tmp)
        self.assertEqual(status, 0, err)
        self.assertEqual(set(os.listdir(os.path.join(self.tmp, 'telemetry'))),
                         {'telemetry.pb.c', 'telemetry.pb.h', 'telemetry_validate.c', 'telemetry_validate.h'})

    def test_units_names_only(self):
        status, result, err = run_backend('units', '--protos-root', FIXTURES, '--names-only')
        self.assertEqual(status, 0, err)
        self.assertEqual(result['units'], ['envelope', 'telemetry'])
        self.assertEqual(result['merged_into'], {})

    def test_units_imported_by_another_unit(self):
        status, result, err = run_backend('units', '--protos-root', STRESS_PROTOS, '--names-only')
        self.assertEqual(status, 0, err)
        # fleet imports "shared/units.proto": fleet.c already contains shared's code.
        self.assertEqual(result['merged_into'], {'shared': ['fleet']})

    def test_gen_c_predicts_filter_modes(self):
        from nanopb_wireshark import predicted_mode, Unit, DEFAULT_NANOPB_ROOT, setup_nanopb
        setup_nanopb(DEFAULT_NANOPB_ROOT)
        unit = Unit(STRESS_PROTOS, 'fleet', [])
        self.assertEqual(predicted_mode(unit, 'fleet.envelope.Envelope'), 'single')  # Any + oneof
        self.assertEqual(predicted_mode(unit, 'fleet.telemetry.Frame'), 'single')    # two Any
        self.assertEqual(predicted_mode(unit, 'fleet.status.Status'), 'auto')

    def test_gen_c_with_runtime_and_without_validation(self):
        status, result, err = run_backend('gen-c', '--protos-root', FIXTURES, '--unit', 'telemetry',
                                          '--out', self.tmp, '--with-runtime', '--no-validate')
        self.assertEqual(status, 0, err)
        files = set(os.listdir(os.path.join(self.tmp, 'telemetry')))
        self.assertTrue({'pb.h', 'pb_encode.c', 'pb_decode.c', 'pb_common.c'} <= files)
        self.assertNotIn('pb_validate.c', files)
        self.assertNotIn('telemetry_validate.c', files)
        with open(os.path.join(self.tmp, 'telemetry', 'telemetry.pb.h')) as handle:
            self.assertNotIn('pb_validate', handle.read())

    def test_gen_data_formats_round_trip(self):
        status, result, err = run_backend('gen-data', '--protos-root', FIXTURES, '--unit', 'envelope',
                                          '--out', self.tmp, '--seed', '5', '--messages', 'Envelope')
        self.assertEqual(status, 0, err)
        data_dir = os.path.join(self.tmp, 'envelope', 'data')
        base = os.path.join(data_dir, 'demo_envelope_Envelope')
        with open(base + '.bin', 'rb') as handle:
            data = handle.read()
        with open(base + '.hex') as handle:
            self.assertEqual(handle.read().strip(), data.hex())
        with open(base + '.h') as handle:
            c_array = handle.read()
        self.assertIn('#define DEMO_ENVELOPE_ENVELOPE_DATA_SIZE %du' % len(data), c_array)
        self.assertIn('static const uint8_t demo_envelope_Envelope_data[%d]' % len(data), c_array)
        self.assertEqual(len(re.findall(r'0x[0-9a-f]{2}', c_array)), len(data))

        from nanopb_data_generator import DataGenerator
        gen = DataGenerator(os.path.join(FIXTURES, 'envelope', 'envelope.proto'),
                            [FIXTURES, os.path.join(os.path.dirname(FIXTURES), '..', '..', 'backend', 'include')])
        msg = gen.registry.get_message_class('demo.envelope.Envelope')()
        msg.ParseFromString(data)
        self.assertIn(msg.body.type_url, ('type.googleapis.com/demo.payloads.Ping',
                                          'type.googleapis.com/demo.payloads.Command'))

    def test_gen_data_count_and_invalid(self):
        status, result, err = run_backend('gen-data', '--protos-root', FIXTURES, '--unit', 'telemetry',
                                          '--out', self.tmp, '--seed', '1', '--count', '2',
                                          '--messages', 'Telemetry', '--invalid', '--formats', 'hex')
        self.assertEqual(status, 0, err)
        names = sorted(os.listdir(os.path.join(self.tmp, 'telemetry', 'data')))
        self.assertEqual(names, ['demo_telemetry_Telemetry_0_invalid.hex', 'demo_telemetry_Telemetry_0_invalid.txt',
                                 'demo_telemetry_Telemetry_1_invalid.hex', 'demo_telemetry_Telemetry_1_invalid.txt'])

    def test_schema_contents(self):
        path = os.path.join(self.tmp, 'schema.luadata')
        status, result, err = run_backend('schema', '--protos-root', FIXTURES, '--out', path)
        self.assertEqual(status, 0, err)
        self.assertIn('google.protobuf.Any', result['messages'])
        self.assertIn('demo.payloads.Command', result['messages'])
        with open(path) as handle:
            text = handle.read()
        self.assertIn('["demo.common.Unit"] = { [0] = "UNIT_UNKNOWN", [1] = "UNIT_CELSIUS", [2] = "UNIT_VOLT" }',
                      text)
        self.assertNotIn('validate.', text)

    def test_install_dissector_and_port_map(self):
        status, result, err = run_backend('install-dissector', '--protos-root', FIXTURES,
                                          '--plugins-dir', self.tmp,
                                          '--port-map', 'udp:5000=demo.envelope.Envelope,tcp:7000=demo.payloads.Ping')
        self.assertEqual(status, 0, err)
        self.assertTrue(os.path.isfile(os.path.join(self.tmp, 'nanopb_any_dissector.lua')))
        with open(os.path.join(self.tmp, 'nanopb', 'ports.luadata')) as handle:
            ports = handle.read()
        self.assertIn('port = 5000, message = "demo.envelope.Envelope"', ports)
        self.assertEqual(result['ports'], ['udp:5000=demo.envelope.Envelope', 'tcp:7000=demo.payloads.Ping'])

    def test_errors(self):
        status, _, err = run_backend('gen-c', '--protos-root', FIXTURES, '--unit', 'nope', '--out', self.tmp)
        self.assertEqual(status, 1)
        self.assertIn('unknown unit(s) nope', err)
        status, _, err = run_backend('install-dissector', '--protos-root', FIXTURES, '--plugins-dir', self.tmp,
                                     '--port-map', 'udp:5000=no.Such')
        self.assertEqual(status, 1)
        self.assertIn('not in the schema', err)
        status, _, err = run_backend('gen-data', '--protos-root', FIXTURES, '--out', self.tmp, '--formats', 'pcap')
        self.assertEqual(status, 1)
        self.assertIn('unknown format', err)

    def test_install_studio_self_contained(self):
        config_path = os.path.join(self.tmp, 'nanopb', 'studio_config.luadata')
        os.makedirs(os.path.dirname(config_path))
        with open(config_path, 'w') as handle:
            handle.write('return {\n  protos_root = "C:\\\\my \\"protos\\"",\n  port_map = "udp:1=a.B",\n}\n')
        status, result, err = run_backend('install-studio', '--plugins-dir', self.tmp)
        self.assertEqual(status, 0, err)
        for name in ('nanopb_studio.lua', 'nanopb_any_dissector.lua'):
            self.assertTrue(os.path.isfile(os.path.join(self.tmp, name)))
        project = os.path.join(self.tmp, 'nanopb', 'project')
        for rel in ('pb.h', 'pb_validate.c', 'pb_filter_macros.h', 'generator/nanopb_generator.py',
                    'generator/proto/validate.proto', 'tools/wireshark/backend/nanopb_wireshark.py',
                    'tools/wireshark/nanopb_any_dissector.lua.src', 'INSTALL_INFO.json'):
            self.assertTrue(os.path.isfile(os.path.join(project, rel)), rel)
        lua_files = [f for _, _, files in os.walk(os.path.join(self.tmp, 'nanopb'))
                     for f in files if f.endswith('.lua')]
        self.assertEqual(lua_files, [])

        from nanopb_wireshark import read_lua_config
        config = read_lua_config(config_path)
        self.assertEqual(config['project'], project)
        self.assertEqual(config['nanopb_root'], '')
        self.assertEqual(config['protos_root'], 'C:\\my "protos"')  # kept from before
        self.assertEqual(config['port_map'], 'udp:1=a.B')

        # The copy works on its own, without the checkout.
        out = os.path.join(self.tmp, 'out')
        run = subprocess.run([sys.executable, os.path.join(project, 'tools', 'wireshark', 'backend',
                                                           'nanopb_wireshark.py'),
                              'gen-c', '--protos-root', FIXTURES, '--unit', 'envelope', '--out', out],
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
        self.assertTrue(run.stdout.rstrip().endswith('__EXIT__=0'), run.stdout)
        self.assertEqual(sorted(os.listdir(os.path.join(out, 'envelope'))),
                         ['envelope.pb.c', 'envelope.pb.h', 'envelope_validate.c', 'envelope_validate.h'])

    def test_install_studio_dev(self):
        status, result, err = run_backend('install-studio', '--plugins-dir', self.tmp, '--dev')
        self.assertEqual(status, 0, err)
        from nanopb_wireshark import DEFAULT_NANOPB_ROOT, read_lua_config
        config = read_lua_config(os.path.join(self.tmp, 'nanopb', 'studio_config.luadata'))
        self.assertEqual(config['nanopb_root'], DEFAULT_NANOPB_ROOT)


if __name__ == '__main__':
    unittest.main()
