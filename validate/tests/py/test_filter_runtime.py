"""The protocol filter at run time: packets of the stress example (Any inside
Any, repeated Any, Any in a oneof, Any inside a sub-message) go through
fleet_udp/fleet_tcp, built once with payloads on the stack and once with
PB_VALIDATE_FILTER_STATIC_BUFFERS.

The static build gets the case that would break if a message decoded at two
nesting levels shared one buffer: an outer Batch whose first item is a Batch
and whose second item must still be checked after the inner one returns.
"""

import os
import shutil
import subprocess
import tempfile
import unittest

from helpers import STRESS_PROTOS, any_of, f_bytes, f_sint, f_varint, run_backend, unit_build
from test_backend import find_cc

ALLOW, DROP = 0, -1


def setmode(mode):
    return any_of('fleet.cmd.SetMode', f_varint(1, mode))


def imu(temp_c):
    return any_of('fleet.sensors.Imu', f_sint(3, temp_c))


def batch(*items):
    return any_of('fleet.envelope.Batch', b''.join(f_bytes(1, item) for item in items))


def envelope(body_field, body, major=2):
    version = f_bytes(1, f_varint(1, major)) if major is not None else b''
    return any_of('fleet.envelope.Envelope', version + f_bytes(body_field, body))


def frame(readings=(), primary=None, device=True):
    body = f_bytes(1, f_bytes(3, 'dev-alpha')) if device else b''
    body += b''.join(f_bytes(4, r) for r in readings)
    if primary is not None:
        body += f_bytes(7, primary)
    return body


def nested_batches(levels):
    packet = setmode(1)
    for _ in range(levels):
        packet = batch(packet)
    return packet


CASES = [
    ('SetMode', setmode(2), ALLOW),
    ('SetMode with an undefined enum value', setmode(7), DROP),
    ('Imu', imu(25), ALLOW),
    ('Imu out of range', imu(200), DROP),
    ('unknown type_url', any_of('nope.Nope', b''), DROP),
    ('not an Any', b'\xff\xff\xff', DROP),
    ('truncated', setmode(2)[:-3], DROP),
    ('Envelope.extension (Any in a oneof)', envelope(5, setmode(1)), ALLOW),
    ('Envelope.extension with a bad payload', envelope(5, setmode(9)), DROP),
    ('Envelope without its required version', envelope(5, setmode(1), major=None), DROP),
    ('Envelope.frame: Any inside a sub-message', envelope(2, frame([imu(1), imu(2)], imu(3))), ALLOW),
    ('Envelope.frame: bad repeated Any', envelope(2, frame([imu(1), imu(500)])), DROP),
    ('Envelope.frame: bad optional Any', envelope(2, frame([], imu(-99))), DROP),
    ('Envelope.frame: primary not on its any.in list', envelope(2, frame([], setmode(1))), DROP),
    ('Envelope.frame without its required device', envelope(2, frame([imu(1)], device=False)), DROP),
    ('Batch in Batch, then a valid item', batch(batch(setmode(1)), setmode(2)), ALLOW),
    # One shared buffer per message would let the inner Batch overwrite the outer
    # one (items_count 1): the second, unknown item would never be looked at.
    ('Batch in Batch, then an unknown item', batch(batch(setmode(1)), any_of('nope.Nope', b'')), DROP),
    ('Batch in Batch, then a bad item', batch(batch(setmode(1)), setmode(8)), DROP),
    ('Envelope.batch with Envelopes inside', envelope(6, f_bytes(1, envelope(5, setmode(1)))
                                                     + f_bytes(1, batch(setmode(2)))), ALLOW),
    # The outer packet is an Any, so Batch(Batch(Batch(SetMode))) is four Anys deep: the limit.
    ('4 Anys nested (the limit)', nested_batches(3), ALLOW),
    ('5 Anys nested', nested_batches(4), DROP),
    # The outer Any is read in place: a long type_url is just a name that is not in the
    # protocol, a long payload is fine if it is a valid message.
    ('long type_url that is not a message of the protocol', any_of('x' * 90 + '.Msg', b''), DROP),
    ('payload that is not a message (600 zero bytes)', any_of('fleet.cmd.SetMode', b'\x00' * 600), DROP),
    ('payload with 600 bytes of unknown fields after a valid SetMode',
     any_of('fleet.cmd.SetMode', f_varint(1, 2) + f_bytes(15, b'\x01' * 597)), ALLOW),
]


def c_array(data):
    return '{' + ', '.join('0x%02x' % b for b in bytearray(data)) + '}' if data else '{0}'


def harness(cases):
    lines = ['#include <stdio.h>', '#include "fleet.pb.h"', '',
             'static int failed;', '',
             'static void check(const char *name, const uint8_t *data, size_t size, int want)',
             '{',
             '    int udp = fleet_udp(NULL, data, size);',
             '    int tcp = fleet_tcp(NULL, data, size, true);',
             '    if (udp != want || tcp != want) {',
             '        printf("FAIL %s: udp %d tcp %d, want %d\\n", name, udp, tcp, want);',
             '        failed++;',
             '    }',
             '}', '', 'int main(void)', '{']
    for i, (name, data, want) in enumerate(cases):
        lines.append('    { static const uint8_t p%d[] = %s; check("%s", p%d, %d, %d); }'
                     % (i, c_array(data), name, i, len(data), want))
    lines += ['    printf("%d failed\\n", failed);', '    return failed != 0;', '}', '']
    return '\n'.join(lines)


class FilterRuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix='nanopb_ws_filter_rt_')
        # This protocol nests Anys on purpose, so it needs room: --any-value-size 512.
        cls.out = os.path.join(cls.tmp, 'out')
        status, _, err = run_backend('gen-c', '--protos-root', STRESS_PROTOS, '--out', cls.out,
                                     '--with-runtime', '--unit', 'fleet', '--any-value-size', '512')
        assert status == 0, err
        # The default: value = the largest message without an Any (Imu, 128 bytes).
        cls.exact = os.path.join(cls.tmp, 'exact')
        status, _, err = run_backend('gen-c', '--protos-root', STRESS_PROTOS, '--out', cls.exact,
                                     '--with-runtime', '--unit', 'fleet')
        assert status == 0, err

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_one_function(self):
        """One public filter, fleet_udp/fleet_tcp; the rest is static: <unit>_check_any, one check
        function per message (each with only its own struct on the stack) and the fast path."""
        with open(os.path.join(self.out, 'fleet', 'fleet.pb.c')) as handle:
            text = handle.read()
        import re
        public = re.findall(r'^int (\w+)\(', text, re.M)
        self.assertEqual(public, ['fleet_udp', 'fleet_tcp'])
        self.assertIn('static int fleet_check_any(', text)
        self.assertIn('FLEET_FILTER_MESSAGE("fleet.cmd.Move", fleet_check_cmd_Move);', text)
        with open(os.path.join(self.out, 'fleet', 'fleet.pb.h')) as handle:
            header = handle.read()
        self.assertEqual(re.findall(r'^int (\w+)\(', header, re.M), ['fleet_udp', 'fleet_tcp'])

    def run_cases(self, defines, cases=CASES, out=None, tag=''):
        cc = find_cc()
        if not cc:
            self.skipTest('no C compiler')
        unit_dir = os.path.join(out or self.out, 'fleet')
        flags, extra = unit_build(unit_dir)
        build = os.path.join(self.tmp, 'build_' + ('static' if defines else 'stack') + tag)
        os.makedirs(build)
        main = os.path.join(build, 'main.c')
        with open(main, 'w', newline='\n') as handle:
            handle.write(harness(cases))
        sources = [main] + [os.path.join(unit_dir, f) for f in sorted(os.listdir(unit_dir)) if f.endswith('.c')]
        objects = []
        for source in sources + extra:
            obj = os.path.join(build, os.path.basename(source) + '.o')
            proc = subprocess.run(cc + ['-std=c99', '-Wall', '-Wextra', '-Werror'] + defines + flags
                                  + ['-c', source, '-o', obj], stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT, universal_newlines=True)
            self.assertEqual(proc.returncode, 0, source + ': ' + proc.stdout[-3000:])
            objects.append(obj)
        exe = os.path.join(build, 'filter_rt' + ('.exe' if os.name == 'nt' else ''))
        proc = subprocess.run(cc + ['-o', exe] + objects, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, universal_newlines=True)
        self.assertEqual(proc.returncode, 0, proc.stdout[-3000:])
        proc = subprocess.run([exe], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
        self.assertEqual(proc.returncode, 0, proc.stdout)
        self.assertIn('0 failed', proc.stdout)

    def test_stack_payloads(self):
        self.run_cases([])

    def test_static_payloads(self):
        self.run_cases(['-DPB_VALIDATE_FILTER_STATIC_BUFFERS'])

    def test_optimized_with_undefined_behavior_checks(self):
        """-O2 lets the compiler exploit undefined behavior; UBSan (trap mode, no runtime
        needed) stops the program at the first one. Every case must still be right."""
        ubsan = ['-fsanitize=undefined', '-fsanitize-trap=undefined']
        self.run_cases(['-O2'] + ubsan, tag='_o2_ubsan')
        self.run_cases(['-O2', '-DPB_VALIDATE_FILTER_STATIC_BUFFERS'] + ubsan, tag='_o2_ubsan_static')

    def test_default_value_size_fits_one_level_of_nesting(self):
        """Without --any-value-size, Any.value is nanopb's largest message size with its Anys
        holding the largest message without one (Envelope with Imus: 1053 bytes): any message
        with one level of Any fits. The outer Any is read in place, so the packet itself may be
        bigger; an Any inside a message holding more than that is dropped (gen warns)."""
        with open(os.path.join(self.exact, 'fleet', 'fleet.pb.h')) as handle:
            header = handle.read()
        self.assertIn('PB_BYTES_ARRAY_T(1053) fleet_google_protobuf_Any_value_t', header)
        one_level = envelope(2, frame([imu(-40), imu(125), imu(1)], imu(3)))
        envelopes = [envelope(2, frame([imu(-40), imu(125), imu(1)], imu(3))) for _ in range(3)]
        big = batch(*[batch(*envelopes) for _ in range(3)])
        self.assertGreater(len(big), 49 + 1053 + 6)          # more than type_url + value + tags
        inner_too_big = batch(big)                            # an Any inside a Batch holding it
        self.run_cases([], cases=[
            ('Imu, the largest message without an Any', imu(-40), ALLOW),
            ('Envelope.frame with three Imus and a primary: one level of Any', one_level, ALLOW),
            ('a 3 KB packet: the outer Any is read in place, not copied', big, ALLOW),
            ('an Any inside a message holding more than Any.value', inner_too_big, DROP),
        ], out=self.exact, tag='_exact')


if __name__ == '__main__':
    unittest.main()
