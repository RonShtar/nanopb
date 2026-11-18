"""The filter's fast path (nanopb_validate/fast_decode.py) gives pb_decode's verdict on every packet.

Each protocol is built twice: with the fast path (and PB_VALIDATE_FILTER_TEST_POISON, which
fills the decode struct with 0xA5 first, so a field the fast decoder forgot to initialize
changes a verdict) and with PB_VALIDATE_FILTER_NO_FAST_DECODE (pb_decode only). Both get the
same packets: the generated valid and invalid ones, every field of them duplicated (nanopb
merges a sub-message seen twice, the last scalar wins), truncations, bit flips, inserted and
deleted bytes and over-long varints. The verdicts must be identical.
"""

import json
import os
import random
import shutil
import struct
import subprocess
import tempfile
import unittest

from helpers import STRESS_PROTOS, run_backend
from test_backend import find_cc

# Every kind of field: scalars of every type and int_size, packed and unpacked repeated,
# strings, bytes, fixed-length bytes, maps, oneofs with scalars / messages / Anys, Anys
# nested and repeated, proto2 required fields and defaults.
KINDS = '''syntax = "proto3";
package kinds;
import "validate.proto";
import "google/protobuf/any.proto";
enum Color { RED = 0; GREEN = 1; BLUE = 2; }
message Scalars {
  bool b = 1; int32 i32 = 2 [(validate.rules).int32 = {gte: -1000, lte: 1000}]; int64 i64 = 3;
  uint32 u32 = 4 [(validate.rules).uint32.lt = 4000000000]; uint64 u64 = 5;
  sint32 s32 = 6 [(validate.rules).sint32.gt = -50]; sint64 s64 = 7; fixed32 f32 = 8; fixed64 f64 = 9;
  sfixed32 sf32 = 10; sfixed64 sf64 = 11; float fl = 12 [(validate.rules).float = {gte: -10, lte: 10}];
  double db = 13; Color color = 14 [(validate.rules).enum.defined_only = true];
  optional uint32 opt = 15 [(validate.rules).uint32.gte = 3];
  int32 i8 = 16; int32 i16 = 17; uint32 u8 = 18 [(validate.rules).uint32.lte = 200]; sint32 s8 = 19; Color c8 = 20;
}
message Inner {
  uint32 v = 1 [(validate.rules).uint32.lte = 100];
  google.protobuf.Any any = 2;
  repeated google.protobuf.Any anys = 3 [(validate.rules).repeated.max_items = 2];
}
message Texts {
  string s = 1 [(validate.rules).string = {min_len: 1, max_len: 12, prefix: "k"}];
  bytes data = 2 [(validate.rules).bytes.max_len = 20]; bytes fixed = 3; string free = 4;
}
message Lists {
  repeated uint32 pu = 1 [(validate.rules).repeated = {min_items: 1, max_items: 6}];
  repeated sint64 ps = 2; repeated fixed32 pf = 3; repeated bool pb = 4;
  repeated string names = 5 [(validate.rules).repeated.unique = true]; repeated bytes blobs = 6;
  repeated Inner inners = 7; map<string, int32> m = 8; repeated double pd = 9;
  repeated Color pc = 10 [(validate.rules).repeated.items.enum.defined_only = true];
}
message Choice {
  oneof c { uint32 n = 1 [(validate.rules).uint32.gt = 2]; string t = 2; Inner in = 3;
            google.protobuf.Any a = 4; Texts tx = 5; }
  uint32 after = 6;
}
message Holder {
  Inner one = 1; repeated Inner many = 2; google.protobuf.Any top = 3; Choice ch = 4;
  Scalars sc = 5; Lists ls = 6; Texts tx = 7;
}
'''
LEGACY = '''syntax = "proto2";
package kinds;
import "validate.proto";
enum Level { LOW = 3; HIGH = 4; }
message Req { required uint32 a = 1 [(validate.rules).uint32.lte = 50]; required bool b = 2;
              optional string name = 3; optional Sub sub = 4; }
message Sub { required int32 x = 1; optional uint32 y = 2 [(validate.rules).uint32.gt = 1]; }
message WithDefault { required uint32 id = 1; optional int32 d = 2 [default = 5, (validate.rules).int32.gt = 1]; }
message WithEnum { optional Level level = 1; optional uint32 n = 2; }
'''
KINDS_OPTIONS = '''kinds.Scalars.i8 int_size:IS_8
kinds.Scalars.i16 int_size:IS_16
kinds.Scalars.u8 int_size:IS_8
kinds.Scalars.s8 int_size:IS_8
kinds.Scalars.c8 int_size:IS_8
kinds.Inner.anys max_count:2
kinds.Texts.s max_size:13
kinds.Texts.data max_size:24
kinds.Texts.fixed max_size:4 fixed_length:true
kinds.Texts.free max_size:16
kinds.Lists.pu max_count:6
kinds.Lists.ps max_count:4
kinds.Lists.pf max_count:4
kinds.Lists.pb max_count:5
kinds.Lists.names max_count:3 max_size:8
kinds.Lists.blobs max_count:2 max_size:6
kinds.Lists.inners max_count:2
kinds.Lists.m max_count:3
kinds.Lists.MEntry.key max_size:6
kinds.Lists.pd max_count:3
kinds.Lists.pc max_count:4
kinds.Choice.t max_size:10
kinds.Holder.many max_count:2
'''
ANY_VALUE = '512'       # keeps the nested structs (and the stack) small


def varint(n):
    out = b''
    while True:
        b, n = n & 0x7F, n >> 7
        if not n:
            return out + bytes([b])
        out += bytes([b | 0x80])


def fields(data):
    """[(tag, raw field bytes, body of a length-delimited field or None)] or None."""
    out, i = [], 0
    try:
        while i < len(data):
            start, key, shift = i, 0, 0
            while True:
                b = data[i]
                i += 1
                key |= (b & 0x7F) << shift
                shift += 7
                if not b & 0x80:
                    break
            wire, body = key & 7, None
            if wire == 0:
                while data[i] & 0x80:
                    i += 1
                i += 1
            elif wire == 1:
                i += 8
            elif wire == 5:
                i += 4
            elif wire == 2:
                n, shift = 0, 0
                while True:
                    b = data[i]
                    i += 1
                    n |= (b & 0x7F) << shift
                    shift += 7
                    if not b & 0x80:
                        break
                body, i = data[i:i + n], i + n
            else:
                return None
            if i > len(data):
                return None
            out.append((key >> 3, data[start:i], body))
    except IndexError:
        return None
    return out


def corpus(seeds, count, seed):
    rng = random.Random(seed)
    out = list(seeds)
    for pkt in seeds:
        top = fields(pkt) or []
        urls = [f[2] for f in top if f[0] == 1]
        values = [f[2] for f in top if f[0] == 2]
        if not urls or not values:
            continue
        url, value = urls[-1], values[-1]

        def wrap(v):
            return b'\x0a' + varint(len(url)) + url + b'\x12' + varint(len(v)) + v
        inner = fields(value) or []
        out += [wrap(value + value), pkt + pkt]                     # every field twice
        for f in inner[:6]:
            out += [wrap(value + f[1]), wrap(f[1] + value)]
            if f[2] and fields(f[2]):                              # a field of a sub-message twice
                sub = fields(f[2])[-1]
                body = f[2] + sub[1]
                key = varint(f[0] << 3 | 2)
                out.append(wrap(value.replace(f[1], key + varint(len(body)) + body, 1)))
        out.append(wrap(b''.join(f[1] for f in reversed(inner))))
    base = list(out)
    while len(out) < count:
        data = bytearray(rng.choice(base))
        for _ in range(rng.randrange(1, 3)):
            if not data:
                data = bytearray(b'\x08')
            op, i = rng.randrange(6), rng.randrange(len(data))
            if op == 0:
                data = data[:i]
            elif op == 1:
                data[i] ^= 1 << rng.randrange(8)
            elif op == 2:
                data[i] = rng.choice([0, 0x7F, 0x80, 0xFF, rng.randrange(256)])
            elif op == 3:
                data[i:i] = bytes([rng.randrange(256)])
            elif op == 4:
                del data[i]
            else:
                data[i:i] = rng.choice([b'\xff' * 10 + b'\x01', b'\x80' * 11, b'\x00', b'\x0b',
                                        varint(rng.randrange(1 << 35))])
        out.append(bytes(data))
    for pkt in seeds:
        out += [pkt[:k] for k in range(0, len(pkt), max(1, len(pkt) // 24))]
    return out


MAIN = r'''#include <stdio.h>
#include "%(unit)s.pb.h"
int main(int argc, char **argv) {
    static unsigned char buf[1 << 16];
    unsigned char hdr[4];
    FILE *f = fopen(argv[1], "rb");
    (void)argc;
    if (!f) return 3;
    while (fread(hdr, 1, 4, f) == 4) {
        unsigned n = hdr[0] | hdr[1] << 8 | hdr[2] << 16 | (unsigned)hdr[3] << 24;
        if (n > sizeof buf || fread(buf, 1, n, f) != n) return 2;
        putchar(%(unit)s_udp(NULL, buf, n) == 0 ? 'P' : 'D');
    }
    fclose(f);
    return 0;
}
'''

BENCH = r'''#include <stdio.h>
#include <time.h>
#include "%(unit)s.pb.h"
static const uint8_t pkts[] = {%(bytes)s};
static const unsigned sizes[] = {%(sizes)s};
int main(void) {
    clock_t t0 = clock();
    volatile int sink = 0;
    int round;
    for (round = 0; round < %(rounds)d; round++) {
        const uint8_t *p = pkts;
        unsigned i;
        for (i = 0; i < sizeof sizes / sizeof sizes[0]; i++) {
            sink += %(unit)s_udp(NULL, p, sizes[i]);
            p += sizes[i];
        }
    }
    printf("%%ld\n", (long)(clock() - t0));
    return sink == 12345;
}
'''


class FastDecodeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cc = find_cc()
        cls.tmp = tempfile.mkdtemp(prefix='nanopb_fast_')
        root = os.path.join(cls.tmp, 'protos')
        os.makedirs(os.path.join(root, 'kinds'))
        for name, text in (('kinds.proto', KINDS), ('legacy.proto', LEGACY), ('kinds.options', KINDS_OPTIONS),
                           ('legacy.options', 'kinds.Req.name max_size:10\n')):
            with open(os.path.join(root, 'kinds', name), 'w') as handle:
                handle.write(text)
        cls.roots = {'kinds': root, 'fleet': STRESS_PROTOS}

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def generate(self, unit):
        out = os.path.join(self.tmp, unit)
        if os.path.isdir(os.path.join(out, 'gen')):
            return out
        root = self.roots[unit]
        status, result, err = run_backend('gen-packets', '--mode', 'protocol', '--protos-root', root, '--unit', unit,
                                          '--out', os.path.join(out, 'packets'), '--no-install', '--valid', '3',
                                          '--max-invalid', '30', '--any-value-size', ANY_VALUE,
                                          '--plugins-dir', os.path.join(out, 'plugins'))
        self.assertEqual(status, 0, err)
        status, _, err = run_backend('gen-c', '--protos-root', root, '--unit', unit, '--out', os.path.join(out, 'gen'),
                                     '--with-runtime', '--any-value-size', ANY_VALUE)
        self.assertEqual(status, 0, err)
        return out

    def seeds(self, out):
        with open(os.path.join(out, 'packets', 'nanopb_test_packets.json')) as handle:
            return [bytes.fromhex(p['hex']) for p in json.load(handle)['packets']]

    def build(self, out, unit, tag, main, defines, flags=('-O2',)):
        src = os.path.join(out, 'gen', unit)
        with open(os.path.join(src, 'main_%s.c' % tag), 'w', newline='\n') as handle:
            handle.write(main)
        sources = [os.path.join(src, n) for n in sorted(os.listdir(src))
                   if n.endswith('.c') and (not n.startswith('main_') or n == 'main_%s.c' % tag)]
        exe = os.path.join(out, tag + ('.exe' if os.name == 'nt' else ''))
        proc = subprocess.run(self.cc + ['-std=c99', '-Wall', '-Werror', '-I', src]
                              + list(flags) + list(defines) + sources + ['-o', exe],
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
        self.assertEqual(proc.returncode, 0, proc.stdout[-4000:])
        return exe

    def verdicts(self, unit, count, flags=('-O2',)):
        if not self.cc:
            self.skipTest('no C compiler')
        out = self.generate(unit)
        packets = corpus(self.seeds(out), count, 1)
        path = os.path.join(out, 'corpus.bin')
        with open(path, 'wb') as handle:
            for pkt in packets:
                handle.write(struct.pack('<I', len(pkt)) + pkt)
        main = MAIN % {'unit': unit}
        result = {}
        for tag, define in (('fast', '-DPB_VALIDATE_FILTER_TEST_POISON'), ('slow', '-DPB_VALIDATE_FILTER_NO_FAST_DECODE')):
            exe = self.build(out, unit, tag + ''.join(f.strip('-') for f in flags), main, [define] + list(flags[1:]),
                             flags[:1])
            proc = subprocess.run([exe, path], stdout=subprocess.PIPE)
            self.assertEqual(proc.returncode, 0, '%s build of %s exited %d' % (tag, unit, proc.returncode))
            result[tag] = proc.stdout.decode()
        self.assertEqual(len(result['fast']), len(packets))
        self.assertGreater(result['slow'].count('P'), 20)            # valid packets are in the corpus
        differ = [(i, packets[i].hex()) for i in range(len(packets)) if result['fast'][i] != result['slow'][i]]
        self.assertEqual(differ[:5], [], '%d of %d packets differ' % (len(differ), len(packets)))

    def test_every_field_kind_gives_pb_decodes_verdict(self):
        self.verdicts('kinds', 12000)

    def test_stress_protocol_gives_pb_decodes_verdict(self):
        self.verdicts('fleet', 8000)

    def test_with_nanopb_switches(self):
        self.verdicts('kinds', 4000, ('-O2', '-DPB_FIELD_32BIT', '-DPB_BUFFER_ONLY', '-DPB_NO_ERRMSG',
                                      '-DPB_VALIDATE_FILTER_STATIC_BUFFERS'))

    def test_unoptimized_build(self):
        self.verdicts('kinds', 3000, ('-O0',))

    def test_which_messages_take_the_fast_path(self):
        out = self.generate('kinds')
        with open(os.path.join(out, 'gen', 'kinds', 'kinds.pb.c')) as handle:
            text = handle.read()
        for name in ('Scalars', 'Texts', 'Req', 'Sub', 'WithEnum'):
            self.assertIn('KINDS_CHECK_MESSAGE_FAST(kinds_check_%s, kinds_fast_%s,' % (name, name), text)
        for name in ('Inner', 'Lists', 'Choice', 'Holder'):                 # hold Anys: written out
            self.assertIn('int pbf_r = kinds_fast_%s(value, value_size, payload, depth);' % name, text)
        # an explicit proto2 default: pb_decode only
        self.assertIn('KINDS_CHECK_MESSAGE(kinds_check_WithDefault, "kinds.WithDefault"', text)
        # the first enum value of a proto2 enum is a default too: checked on the descriptor
        self.assertIn('PBF_NODEF(kinds_WithEnum)', text)
        self.assertIn('#if !defined(PB_VALIDATE_DEBUG)', text)

    def test_fast_path_is_faster(self):
        if not self.cc:
            self.skipTest('no C compiler')
        out = self.generate('fleet')
        seeds = self.seeds(out)
        args = {'unit': 'fleet', 'bytes': ','.join(str(b) for p in seeds for b in p),
                'sizes': ','.join(str(len(p)) for p in seeds), 'rounds': 3000}
        times = {}
        for tag, define in (('bench_fast', '-DPB_VALIDATE_FILTER_NO_POISON'),
                            ('bench_slow', '-DPB_VALIDATE_FILTER_NO_FAST_DECODE')):
            exe = self.build(out, 'fleet', tag, BENCH % args, [define])
            best = None
            for _ in range(3):
                proc = subprocess.run([exe], stdout=subprocess.PIPE, universal_newlines=True)
                value = int(proc.stdout.strip())
                best = value if best is None else min(best, value)
            times[tag] = best
        self.assertLess(times['bench_fast'], times['bench_slow'], times)


if __name__ == '__main__':
    unittest.main()
