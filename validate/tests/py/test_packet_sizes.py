"""packets --sizes: valid packets of every message in size ranges, IPv4 fragments over the MTU.

small 100-256, medium 400-800, large 900-1470 bytes of packet (the UDP payload the
filter receives), fragmented more than one MTU, or MIN-MAX. A fragmented packet is
written as the IPv4 fragments a real network carries: Wireshark reassembles them, and
the generated C filter gets the whole datagram.
"""

import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest

from helpers import run_backend
from test_backend import find_cc
from traffic import read_capture

PROTO = '''syntax = "proto3";
package bulk;
import "validate.proto";
import "google/protobuf/any.proto";
message Blob {
  bytes data = 1 [(validate.rules).bytes.min_len = 1];
  repeated uint32 xs = 2;
  string name = 3 [(validate.rules).string.min_len = 1];
}
message Tiny { uint32 a = 1 [(validate.rules).uint32.lte = 9]; }
message Packet { google.protobuf.Any payload = 1; }
'''
OPTIONS = 'bulk.Blob.data max_size:4000\nbulk.Blob.xs max_count:200\nbulk.Blob.name max_size:64\n'
SIZES = 'small,medium,large,fragmented,2000-3000'
RANGES = {'small': (100, 256), 'medium': (400, 800), 'large': (900, 1470), 'fragmented': (1473, 65507),
          '2000-3000': (2000, 3000)}


class PacketSizeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix='nanopb_ws_sizes_')
        protos = os.path.join(cls.tmp, 'protos', 'bulk')
        os.makedirs(protos)
        with open(os.path.join(protos, 'bulk.proto'), 'w') as handle:
            handle.write(PROTO)
        with open(os.path.join(protos, 'bulk.options'), 'w') as handle:
            handle.write(OPTIONS)
        cls.protos = os.path.join(cls.tmp, 'protos')
        cls.out = os.path.join(cls.tmp, 'packets')
        cls.status, cls.result, cls.err = run_backend(
            'gen-packets', '--mode', 'protocol', '--protos-root', cls.protos, '--out', cls.out,
            '--no-install', '--sizes', SIZES, '--plugins-dir', os.path.join(cls.tmp, 'plugins'))
        with open(cls.result['manifest']) as handle:
            cls.manifest = json.load(handle)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def sized(self, message):
        return [e for e in self.manifest['packets'] if e['message'] == message and e['size_class']]

    def test_every_range_gets_a_packet_of_its_size(self):
        self.assertEqual(self.status, 0, self.err)
        got = dict((e['size_class'], e) for e in self.sized('bulk.Blob'))
        self.assertEqual(sorted(got), sorted(RANGES))
        for name, (low, high) in RANGES.items():
            self.assertTrue(low <= got[name]['size'] <= high, (name, got[name]['size']))
            self.assertEqual(got[name]['expect'], 'passed')
        for name in RANGES:                       # Blob reaches every range; the counts are reported
            self.assertGreaterEqual(self.result['sizes'][name], 1, name)
        self.assertIn('Sizes: small 100-256 bytes', self.result['summary'])

    def test_a_range_a_message_cannot_reach_is_reported(self):
        self.assertEqual(self.sized('bulk.Tiny'), [])
        notes = [s for s in self.result['skipped'] if s.startswith('bulk.Tiny small')]
        self.assertEqual(len(notes), 1, self.result['skipped'])
        self.assertRegex(notes[0], r'its valid packets are \d+ to \d+ bytes')

    def test_more_than_the_mtu_is_written_as_fragments_and_read_back_whole(self):
        entries = self.manifest['packets']
        big = [e for e in entries if e['size'] > 1472]
        self.assertTrue(big)
        for e in big:
            self.assertEqual(e['fragments'], -(-(e['size'] + 8) // 1480))     # 1480 bytes of UDP per fragment
        for e in entries:
            if e['size'] <= 1472:
                self.assertEqual(e['fragments'], 1)
        # frame numbers count fragments: each entry's frame is its last fragment
        self.assertEqual(entries[-1]['frame'], sum(e['fragments'] for e in entries))
        packets = read_capture(self.result['pcap'])
        self.assertEqual(len(packets), len(entries))
        for packet, entry in zip(packets, entries):
            self.assertEqual(packet.payload.hex(), entry['hex'])

    def test_wireshark_reassembles_and_gives_every_verdict(self):
        import test_tshark
        live_test = test_tshark.live_test
        if test_tshark.TSHARK is None:
            self.skipTest('tshark not found')
        env = dict(os.environ, WIRESHARK_CONFIG_DIR=os.path.join(self.tmp, 'config'),
                   NANOPB_WS_SCHEMA=os.path.join(self.tmp, 'plugins', 'nanopb', 'schema.luadata'),
                   NANOPB_WS_PORTS=os.path.join(self.tmp, 'no_ports.luadata'))
        os.makedirs(env['WIRESHARK_CONFIG_DIR'], exist_ok=True)
        if not os.path.isfile(env['NANOPB_WS_SCHEMA']):
            from wireshark import write_schema
            write_schema(self.protos, [], env['NANOPB_WS_SCHEMA'])
        args = [test_tshark.TSHARK, '-X', 'lua_script:' + os.path.join(test_tshark.TOOL_DIR, 'nanopb_any_dissector.lua'),
                '-o', 'nanopb.port_map:' + self.manifest['port_map'], '-r', self.result['pcap']]
        for entry in self.manifest['protocol_ports']:
            transport, rest = entry.split(':')
            port, name = rest.split('=')
            args += ['-d', '%s.port==%s,%s' % (transport, port, name.lower())]
        status, out = live_test.run(args + ['-T', 'fields', '-e', 'frame.number', '-e', 'nanopb.validation'], env)
        self.assertEqual(status, 0, out)
        verdicts = {}
        for line in out.splitlines():
            parts = line.split('\t') + ['']
            if parts[0].isdigit() and parts[1]:
                verdicts[int(parts[0])] = parts[1]
        for entry in self.manifest['packets']:
            self.assertEqual(verdicts.get(entry['frame']), entry['expect'], entry['message'] + str(entry['size']))

    def test_the_c_filter_takes_every_sized_packet(self):
        cc = find_cc()
        if not cc:
            self.skipTest('no C compiler')
        gen = os.path.join(self.tmp, 'gen')
        status, _, err = run_backend('gen-c', '--protos-root', self.protos, '--out', gen, '--with-runtime')
        self.assertEqual(status, 0, err)
        unit = os.path.join(gen, 'bulk')
        lines = ['#include <stdio.h>', '#include "bulk.pb.h"', 'int main(void) {', '    int bad = 0;']
        for i, entry in enumerate(self.manifest['packets']):
            data = bytes.fromhex(entry['hex'])
            lines.append('    { static const uint8_t p[] = {%s}; if (bulk_udp(NULL, p, sizeof p) != %d) '
                         '{ printf("WRONG %d\\n"); bad++; } }'
                         % (', '.join(str(b) for b in data), 0 if entry['expect'] == 'passed' else -1, i))
        lines += ['    printf("%d wrong\\n", bad);', '    return bad != 0;', '}', '']
        with open(os.path.join(unit, 'main.c'), 'w', newline='\n') as handle:
            handle.write('\n'.join(lines))
        objects = []
        for name in sorted(os.listdir(unit)):
            if name.endswith('.c'):
                obj = os.path.join(self.tmp, name + '.o')
                proc = subprocess.run(cc + ['-std=c99', '-O2', '-w', '-I', unit, '-c', os.path.join(unit, name),
                                            '-o', obj], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                      universal_newlines=True)
                self.assertEqual(proc.returncode, 0, proc.stdout)
                objects.append(obj)
        exe = os.path.join(self.tmp, 'sizes' + ('.exe' if os.name == 'nt' else ''))
        proc = subprocess.run(cc + ['-o', exe] + objects, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              universal_newlines=True)
        self.assertEqual(proc.returncode, 0, proc.stdout)
        proc = subprocess.run([exe], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
        self.assertIn('0 wrong', proc.stdout)

    def test_bad_size_option(self):
        status, _, err = run_backend('gen-packets', '--mode', 'protocol', '--protos-root', self.protos,
                                     '--out', os.path.join(self.tmp, 'x'), '--no-install', '--sizes', 'huge')
        self.assertEqual(status, 1)
        self.assertIn('small, medium, large, fragmented or MIN-MAX', err)


if __name__ == '__main__':
    unittest.main()
