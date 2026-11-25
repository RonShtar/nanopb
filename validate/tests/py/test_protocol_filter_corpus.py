"""Protocol filters on generated and mutated packets, in every build configuration.

The filter decodes each message with pb_decode and checks it with its validator; the
outer Any and the type_url lookup are pb_validate.c's pb_filter_read_any() and
pb_filter_find_route(). Each protocol is built at -O2, -O0, with nanopb's switches
(PB_FIELD_32BIT PB_BUFFER_ONLY PB_NO_ERRMSG) and with PB_VALIDATE_FILTER_STATIC_BUFFERS.
Every build gets the same packets: the generated valid and invalid ones (each must get
its expected verdict), every field of them duplicated (nanopb merges a sub-message seen
twice, the last scalar wins), truncations, bit flips, inserted and deleted bytes and
over-long varints. Every build must give the same verdict on every packet.
"""

import json
import os
import random
import re
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

RUNTIME_TEST = r'''#include <stdio.h>
#include <string.h>
#include <pb_validate.h>
static int failed;
#define EXPECT(cond, what) do { if (!(cond)) { printf("FAIL %s\n", what); failed++; } } while (0)
static int check_a(const pb_byte_t *v, size_t n, int d) { (void)v; (void)n; (void)d; return 1; }
static int check_b(const pb_byte_t *v, size_t n, int d) { (void)v; (void)n; (void)d; return 2; }
static int check_c(const pb_byte_t *v, size_t n, int d) { (void)v; (void)n; (void)d; return 3; }
static const pb_filter_route_t routes[] = {
    /* "Aa" and "BB" share their hash: both must still be found. */
    { 2112u, "Aa", check_a },
    { 2112u, "BB", check_b },
    { 0u, "pkg.Msg", check_c },   /* fixed below: the hash is computed at run time */
};
static pb_filter_route_t table[3];
static int route(const char *url, size_t size)
{
    const pb_filter_route_t *r = pb_filter_find_route(table, 3, url, size);
    return r ? r->check(NULL, 0, 0) : 0;
}
int main(void)
{
    pb_filter_any_t any;
    uint32_t h = pb_filter_type_hash("pkg.Msg", 7);
    memcpy(table, routes, sizeof routes);
    table[2].hash = h;
    if (h < 2112u) {                  /* keep the table sorted by hash */
        table[0] = routes[2]; table[0].hash = h; table[1] = routes[0]; table[2] = routes[1];
    }
    EXPECT(pb_filter_type_hash("Aa", 2) == 2112u && pb_filter_type_hash("BB", 2) == 2112u, "hash");
    EXPECT(route("Aa", 2) == 1, "Aa");
    EXPECT(route("BB", 2) == 2, "BB (same hash)");
    EXPECT(route("type.googleapis.com/pkg.Msg", 27) == 3, "host prefix");
    EXPECT(route("a/b/pkg.Msg", 11) == 3, "name after the last slash");
    EXPECT(route("pkg.Msg\0junk", 12) == 3, "ends at a NUL");
    EXPECT(route("pkg.Ms", 6) == 0 && route("pkg.Msgs", 8) == 0 && route("", 0) == 0, "no partial names");
    EXPECT(route("Ab", 2) == 0 && route("BB/", 3) == 0, "unknown names");

    /* type_url "ab", value {1,2}, an unknown varint field 3 skipped */
    {
        static const pb_byte_t p[] = { 0x0a, 2, 'a', 'b', 0x18, 0x96, 0x01, 0x12, 2, 1, 2 };
        EXPECT(pb_filter_read_any(p, sizeof p, &any), "read any");
        EXPECT(any.type_url_size == 2 && memcmp(any.type_url, "ab", 2) == 0, "type_url in place");
        EXPECT(any.value == p + 9 && any.value_size == 2, "value in place");
    }
    {
        static const pb_byte_t p[] = { 0x0a, 1, 'a', 0x0a, 1, 'b' };     /* last one wins */
        EXPECT(pb_filter_read_any(p, sizeof p, &any) && any.type_url[0] == 'b', "last wins");
        EXPECT(any.value_size == 0, "missing value is empty");
    }
    EXPECT(pb_filter_read_any((const pb_byte_t *)"", 0, &any) && any.type_url_size == 0, "empty packet");
    {
        static const pb_byte_t wrong_type[] = { 0x08, 1 };                 /* field 1 as a varint */
        static const pb_byte_t too_long[] = { 0x0a, 5, 'a' };
        static const pb_byte_t cut_tag[] = { 0x0a, 1, 'a', 0x80 };
        static const pb_byte_t bad_wire[] = { 0x1f, 0 };                   /* wire type 7 */
        EXPECT(!pb_filter_read_any(wrong_type, sizeof wrong_type, &any), "wrong wire type");
        EXPECT(!pb_filter_read_any(too_long, sizeof too_long, &any), "length past the end");
        EXPECT(!pb_filter_read_any(cut_tag, sizeof cut_tag, &any), "packet ends inside a tag");
        EXPECT(!pb_filter_read_any(bad_wire, sizeof bad_wire, &any), "invalid wire type");
    }
    printf("%d failed\n", failed);
    return failed != 0;
}
'''

# Build configurations every verdict must agree across.
CONFIGS = [
    ('O2', ['-O2']),
    ('O0', ['-O0']),
    ('switches', ['-O2', '-DPB_FIELD_32BIT', '-DPB_BUFFER_ONLY', '-DPB_NO_ERRMSG']),
    ('static', ['-O2', '-DPB_VALIDATE_FILTER_STATIC_BUFFERS']),
]


class ProtocolFilterCorpusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cc = find_cc()
        cls.tmp = tempfile.mkdtemp(prefix='nanopb_corpus_')
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

    def manifest(self, out):
        with open(os.path.join(out, 'packets', 'nanopb_test_packets.json')) as handle:
            return json.load(handle)['packets']

    def build(self, src, exe, main, flags, extra_sources=()):
        main_path = exe + '.c'
        with open(main_path, 'w', newline='\n') as handle:
            handle.write(main)
        sources = [os.path.join(src, n) for n in sorted(os.listdir(src)) if n.endswith('.c')]
        proc = subprocess.run(self.cc + ['-std=c99', '-Wall', '-Wextra', '-Werror', '-I', src] + list(flags)
                              + [main_path] + sources + list(extra_sources) + ['-o', exe],
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
        self.assertEqual(proc.returncode, 0, proc.stdout[-4000:])
        return exe

    def verdicts(self, unit, count):
        """Verdicts of every build configuration on the generated packets plus `count` mutations."""
        if not self.cc:
            self.skipTest('no C compiler')
        out = self.generate(unit)
        manifest = self.manifest(out)
        seeds = [bytes.fromhex(p['hex']) for p in manifest]
        packets = corpus(seeds, count, 1)
        path = os.path.join(out, 'corpus.bin')
        with open(path, 'wb') as handle:
            for pkt in packets:
                handle.write(struct.pack('<I', len(pkt)) + pkt)
        result = {}
        for tag, flags in CONFIGS:
            exe = self.build(os.path.join(out, 'gen', unit), os.path.join(out, 'run_' + tag + EXE),
                             MAIN % {'unit': unit}, flags)
            proc = subprocess.run([exe, path], stdout=subprocess.PIPE)
            self.assertEqual(proc.returncode, 0, '%s build of %s exited %d' % (tag, unit, proc.returncode))
            result[tag] = proc.stdout.decode()
            self.assertEqual(len(result[tag]), len(packets), tag)
        # The generated packets come first in the corpus, each with its expected verdict.
        want = ''.join('P' if p['expect'] == 'passed' else 'D' for p in manifest)
        for tag, got in result.items():
            wrong = [manifest[i]['message'] for i in range(len(want)) if got[i] != want[i]]
            self.assertEqual(wrong, [], '%s build: generated packets with the wrong verdict' % tag)
        self.assertGreater(want.count('P'), 20)
        reference = result['O2']
        for tag, got in result.items():
            differ = [packets[i].hex() for i in range(len(packets)) if got[i] != reference[i]]
            self.assertEqual(differ[:5], [], '%s build: %d of %d packets differ from -O2'
                             % (tag, len(differ), len(packets)))

    def test_every_field_kind(self):
        self.verdicts('kinds', 12000)

    def test_stress_protocol(self):
        self.verdicts('fleet', 8000)

    def test_generated_filter_uses_pb_decode_and_the_library(self):
        """Per message: pb_decode + its validator. Dispatch and the outer Any: pb_validate.c.
        No decoder of its own, no macros, no inline helpers."""
        out = self.generate('kinds')
        with open(os.path.join(out, 'gen', 'kinds', 'kinds.pb.c')) as handle:
            text = handle.read()
        body = text[text.index('kinds_check_any_field(const'):]
        for name in ('Scalars', 'Texts', 'Req', 'Sub', 'WithEnum', 'WithDefault', 'Inner', 'Holder'):
            self.assertIn('pb_decode(&stream, kinds_%s_fields, ' % name, body)
        self.assertIn('pb_filter_read_any(packet, packet_size, &any)', body)
        self.assertIn('pb_filter_find_route(kinds_routes,', body)
        self.assertIn('static const pb_filter_route_t kinds_routes[] = {', body)
        for banned in ('#define', 'inline', 'pb_decode_tag', 'pb_decode_varint', 'switch (key', 'pbf_', 'PBF_'):
            self.assertNotIn(banned, body)
        # The route table is sorted by hash (pb_filter_find_route searches it binary).
        hashes = [int(h, 16) for h in re.findall(r'\{ 0x([0-9a-f]{8})u, "', body)]
        self.assertEqual(hashes, sorted(hashes))
        self.assertEqual(len(hashes), 10)

    def test_runtime_helpers(self):
        if not self.cc:
            self.skipTest('no C compiler')
        out = self.generate('kinds')
        exe = self.build(os.path.join(out, 'gen', 'kinds'), os.path.join(out, 'runtime_test' + EXE),
                         RUNTIME_TEST, ['-O2'])
        proc = subprocess.run([exe], stdout=subprocess.PIPE, universal_newlines=True)
        self.assertEqual(proc.returncode, 0, proc.stdout)


EXE = '.exe' if os.name == 'nt' else ''

if __name__ == '__main__':
    unittest.main()
