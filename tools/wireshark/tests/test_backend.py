"""Tests for tools/wireshark/backend/nanopb_wireshark.py.

Run: python -m unittest discover -s tools/wireshark/tests -v
Needs: protobuf, grpcio-tools (same as the nanopb generator).
"""

import os
import re
import shutil
import tempfile
import unittest

from helpers import FIXTURES, run_backend


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
            self.assertEqual(sorted(os.listdir(unit_dir)), [unit + '.c', unit + '.h'])
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
