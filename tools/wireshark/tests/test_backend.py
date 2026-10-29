"""Tests for tools/wireshark/backend/nanopb_wireshark.py.

Run: python -m unittest discover -s tools/wireshark/tests -v
Needs: protobuf, grpcio-tools (same as the nanopb generator).
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

from helpers import FIXTURES, TOOL_DIR, f_bytes, f_varint, run_backend

STRESS_PROTOS = os.path.join(TOOL_DIR, 'examples', 'stress', 'protos')
STRESS_PORTS = 'udp:5100=fleet.envelope.Envelope,tcp:5101=fleet.telemetry.Frame,udp:5102=fleet.status.Status'


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

    def test_gen_c_merges_one_file_per_unit(self):
        status, result, err = run_backend('gen-c', '--protos-root', FIXTURES, '--out', self.tmp)
        self.assertEqual(status, 0, err)
        for unit in ('envelope', 'telemetry'):
            unit_dir = os.path.join(self.tmp, unit)
            generated = [f for f in os.listdir(unit_dir) if not f.startswith('pb')]
            self.assertEqual(sorted(generated), [unit + '.c', unit + '.h'])
            with open(os.path.join(unit_dir, unit + '.h')) as handle:
                header = handle.read()
            with open(os.path.join(unit_dir, unit + '.c')) as handle:
                source = handle.read()
            # Only the unit's own header may be included with quotes.
            self.assertEqual(re.findall(r'#include\s+"([^"]+)"', header), [])
            self.assertEqual(re.findall(r'#include\s+"([^"]+)"', source), [unit + '.h'])
            opens = len(re.findall(r'^\s*#\s*if', header, re.M))
            closes = len(re.findall(r'^\s*#\s*endif', header, re.M))
            self.assertEqual(opens, closes)
            self.assertIn('<pb_validate.h>', header)

        with open(os.path.join(self.tmp, 'envelope', 'envelope.h')) as handle:
            header = handle.read()
        # Dependency (Any) comes before its user, and storage is static.
        self.assertLess(header.index('} google_protobuf_Any;'), header.index('} demo_envelope_Envelope;'))
        self.assertNotIn('pb_callback_t', header)
        self.assertIn('demo_envelope_Envelope_size', header)
        with open(os.path.join(self.tmp, 'envelope', 'envelope.c')) as handle:
            source = handle.read()
        for symbol in ('PB_BIND(demo_envelope_Envelope', 'PB_BIND(google_protobuf_Any',
                       'pb_validate_demo_envelope_Envelope'):
            self.assertIn(symbol, source)

    def test_gen_c_exports_packet_filters(self):
        status, result, err = run_backend('gen-c', '--protos-root', FIXTURES, '--out', self.tmp)
        self.assertEqual(status, 0, err)
        units = dict((u['unit'], u) for u in result['units'])
        # No port map: the roots no other message of the unit refers to.
        self.assertEqual(units['envelope']['filters'], ['demo_envelope_Envelope_filter_udp'])
        self.assertEqual(units['envelope']['filter_entrypoints'],
                         {'from': 'auto', 'modes': {'demo.envelope.Envelope': 'auto'}})
        self.assertEqual(units['telemetry']['filters'], ['demo_telemetry_Telemetry_filter_udp'])
        with open(os.path.join(self.tmp, 'envelope', 'envelope.h')) as handle:
            header = handle.read()
        self.assertIn('int demo_envelope_Envelope_filter_tcp(void *ctx, const uint8_t *packet, '
                      'size_t packet_size, bool is_to_server);', header)
        with open(os.path.join(self.tmp, 'envelope', 'envelope.c')) as handle:
            self.assertIn('static int demo_envelope_Envelope_filter_core(', handle.read())

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

    def test_gen_c_no_filter(self):
        status, result, err = run_backend('gen-c', '--protos-root', FIXTURES, '--unit', 'envelope',
                                          '--out', self.tmp, '--no-filter')
        self.assertEqual(status, 0, err)
        self.assertEqual(result['units'][0]['filters'], [])

    @unittest.skipIf(find_cc() is None, 'no C compiler (gcc/clang/cc, CC, or pip install ziglang)')
    def test_gen_c_output_builds_and_filters(self):
        status, result, err = run_backend('gen-c', '--protos-root', FIXTURES, '--unit', 'telemetry',
                                          '--out', self.tmp)
        self.assertEqual(status, 0, err)
        unit_dir = os.path.join(self.tmp, 'telemetry')
        # device_name has min_len 1: without it the packet is rejected.
        good = f_bytes(1, f_varint(1, 7)) + f_bytes(2, 'dev-1')
        bad = f_bytes(1, f_varint(1, 7)) + f_varint(7, 1)
        main = os.path.join(unit_dir, 'main_check.c')
        with open(main, 'w') as handle:
            handle.write('\n'.join([
                '#include <stdio.h>',
                '#include "telemetry.h"',
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

    def test_gen_c_copies_runtime_as_separate_files(self):
        status, result, err = run_backend('gen-c', '--protos-root', FIXTURES, '--unit', 'telemetry',
                                          '--out', self.tmp)
        self.assertEqual(status, 0, err)
        files = set(os.listdir(os.path.join(self.tmp, 'telemetry')))
        self.assertEqual(files, {'telemetry.c', 'telemetry.h', 'pb.h', 'pb_common.h', 'pb_common.c',
                                 'pb_encode.h', 'pb_encode.c', 'pb_decode.h', 'pb_decode.c',
                                 'pb_validate.h', 'pb_validate.c', 'pb_filter_macros.h'})

    def test_gen_c_no_runtime(self):
        status, result, err = run_backend('gen-c', '--protos-root', FIXTURES, '--unit', 'telemetry',
                                          '--out', self.tmp, '--no-runtime')
        self.assertEqual(status, 0, err)
        self.assertEqual(set(os.listdir(os.path.join(self.tmp, 'telemetry'))), {'telemetry.c', 'telemetry.h'})

    def test_units_names_only(self):
        status, result, err = run_backend('units', '--protos-root', FIXTURES, '--names-only')
        self.assertEqual(status, 0, err)
        self.assertEqual(result['units'], ['envelope', 'telemetry'])

    def test_gen_c_with_runtime_and_without_validation(self):
        status, result, err = run_backend('gen-c', '--protos-root', FIXTURES, '--unit', 'telemetry',
                                          '--out', self.tmp, '--with-runtime', '--no-validate')
        self.assertEqual(status, 0, err)
        files = set(os.listdir(os.path.join(self.tmp, 'telemetry')))
        self.assertTrue({'pb.h', 'pb_encode.c', 'pb_decode.c', 'pb_common.c'} <= files)
        self.assertNotIn('pb_validate.c', files)
        with open(os.path.join(self.tmp, 'telemetry', 'telemetry.h')) as handle:
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

    def test_install_studio_writes_config(self):
        status, result, err = run_backend('install-studio', '--plugins-dir', self.tmp)
        self.assertEqual(status, 0, err)
        self.assertTrue(os.path.isfile(os.path.join(self.tmp, 'nanopb_studio.lua')))
        with open(os.path.join(self.tmp, 'nanopb', 'studio_config.luadata')) as handle:
            self.assertIn('nanopb_root', handle.read())


if __name__ == '__main__':
    unittest.main()
