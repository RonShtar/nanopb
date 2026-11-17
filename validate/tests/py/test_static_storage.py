"""Static storage only: Any.type_url sized to the longest URL, no pb_callback_t, no malloc.

gen sizes google.protobuf.Any.type_url per protocol to exactly the longest
"type.googleapis.com/<message>" the protocol can carry (+ NUL), and refuses to
write a protocol in which a field would be a callback or a pointer.
"""

import os
import re
import shutil
import tempfile
import unittest

from helpers import STRESS_PROTOS, run_backend

ANY_IMPORT = 'import "google/protobuf/any.proto";\n'


class StaticStorageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='nanopb_ws_static_')

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def write(self, rel, text):
        path = os.path.join(self.tmp, 'protos', *rel.split('/'))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w', newline='\n') as handle:
            handle.write(text)

    def gen(self, *extra):
        out = os.path.join(self.tmp, 'out')
        status, result, err = run_backend('gen-c', '--protos-root', os.path.join(self.tmp, 'protos'),
                                          '--out', out, *extra)
        return status, result, err, out

    def header(self, out, unit):
        with open(os.path.join(out, unit, unit + '.pb.h')) as handle:
            return handle.read()

    def test_type_url_is_the_longest_url_plus_nul(self):
        longest = 'radar.tracking.VeryLongMessageNameForTheTest'
        self.write('radar/radar.proto', 'syntax = "proto3";\npackage radar.tracking;\n' + ANY_IMPORT +
                   'message Short { uint32 a = 1; }\n'
                   'message VeryLongMessageNameForTheTest { uint32 b = 1; }\n'
                   'message Packet { google.protobuf.Any payload = 1; }\n')
        status, result, err, out = self.gen()
        self.assertEqual(status, 0, err)
        size = len('type.googleapis.com/' + longest) + 1
        self.assertIn('char type_url[%d];' % size, self.header(out, 'radar'))
        unit = result['units'][0]
        self.assertEqual(unit['any_type_url'], {'max_size': size, 'longest': 'type.googleapis.com/' + longest})
        self.assertIn('Any.type_url: char[%d]' % size, result['summary'])

    def test_project_value_is_replaced_and_any_in_counts(self):
        """A project any.options type_url size is replaced; an any.in URL longer than every
        message name sets the size."""
        url = 'type.example-company-gateway.internal/radar.Short'
        self.write('radar/radar.proto', 'syntax = "proto3";\npackage radar;\n' + ANY_IMPORT +
                   'import "validate.proto";\n'
                   'message Short { uint32 a = 1; }\n'
                   'message Packet { google.protobuf.Any payload = 1 [(validate.rules).any.in = "%s"]; }\n' % url)
        self.write('radar/google/protobuf/any.options',
                   'google.protobuf.Any.type_url max_size:200\ngoogle.protobuf.Any.value max_size:64\n')
        status, _, err, out = self.gen()
        self.assertEqual(status, 0, err)
        header = self.header(out, 'radar')
        self.assertIn('char type_url[%d];' % (len(url) + 1), header)
        self.assertIn('PB_BYTES_ARRAY_T(64)', header)          # value keeps the project's size

    def test_stress_example_is_all_static(self):
        out = os.path.join(self.tmp, 'out')
        status, result, err = run_backend('gen-c', '--protos-root', STRESS_PROTOS, '--out', out, '--unit', 'fleet')
        self.assertEqual(status, 0, err)
        header = self.header(out, 'fleet')
        self.assertIn('char type_url[49];', header)            # type.googleapis.com/fleet.telemetry.Health.Fault
        self.assertNotIn('pb_callback_t', header)
        self.assertEqual(re.findall(r'X\(a, (?:CALLBACK|POINTER)', header), [])

    def test_callback_field_is_refused(self):
        self.write('radar/radar.proto', 'syntax = "proto3";\npackage radar;\n' + ANY_IMPORT +
                   'message Short { string name = 1; repeated uint32 hits = 2; uint32 ok = 3; }\n'
                   'message Packet { google.protobuf.Any payload = 1; }\n')
        status, _, err, out = self.gen()
        self.assertEqual(status, 1)
        self.assertIn('2 field(s) would not be static storage', err)
        self.assertIn('radar_Short.name: CALLBACK string', err)
        self.assertIn('radar_Short.hits: CALLBACK repeated uint32', err)
        self.assertNotIn('radar_Short.ok', err)
        self.assertIn('max_size', err)
        self.assertFalse(os.path.exists(os.path.join(out, 'radar', 'radar.pb.h')))   # nothing half usable

        status, _, err, out = self.gen('--allow-callbacks', '--no-filter')
        self.assertEqual(status, 0, err)
        self.assertIn('pb_callback_t', self.header(out, 'radar'))

    def test_sized_fields_are_accepted(self):
        self.write('radar/radar.proto', 'syntax = "proto3";\npackage radar;\n' + ANY_IMPORT +
                   'message Short { string name = 1; repeated uint32 hits = 2; }\n'
                   'message Packet { google.protobuf.Any payload = 1; }\n')
        self.write('radar/radar.options', 'radar.Short.name max_size:16\nradar.Short.hits max_count:4\n')
        status, _, err, out = self.gen()
        self.assertEqual(status, 0, err)
        header = self.header(out, 'radar')
        self.assertIn('char name[16];', header)
        self.assertIn('uint32_t hits[4];', header)
        self.assertNotIn('pb_callback_t', header)


if __name__ == '__main__':
    unittest.main()
