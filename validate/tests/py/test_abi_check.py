"""pb_validate's layout switches must match between the generated code and pb_validate.c.

PB_VALIDATE_MAX_PATH_DEPTH / _MAX_PATH_LENGTH / _MAX_VIOLATIONS / _MAX_MESSAGE_LENGTH,
PB_VALIDATE_DEBUG and PB_FIELD_32BIT change pb_violations_t and pb_validate_context_t.
Built with different values (e.g. gen's suggested -D values on the generated files only),
the library used to write past the caller's buffers: memory corruption, visible at -O2.
They are part of the runtime's link names now, so such a build does not link.
"""

import os
import shutil
import subprocess
import tempfile
import unittest

from helpers import run_backend
from test_backend import find_cc

PROTO = '''syntax = "proto3";
package demo;
import "validate.proto";
message Frame { uint32 id = 1 [(validate.rules).uint32.gte = 1]; }
'''

MAIN = '''#include <stdio.h>
#include <string.h>
#include "demo.pb.h"
#include "demo_validate.h"

static struct { unsigned char before[64]; pb_violations_t v; unsigned char after[256]; } g;

int main(void)
{
    demo_Frame bad = demo_Frame_init_zero;
    unsigned i, damaged = 0;
    memset(&g, 0xA5, sizeof g);
    pb_violations_init(&g.v);
    if (demo_validate_Frame(&bad, &g.v)) return 2;
    for (i = 0; i < sizeof g.before; i++) damaged += g.before[i] != 0xA5;
    for (i = 0; i < sizeof g.after; i++) damaged += g.after[i] != 0xA5;
    printf("violations=%u path=%s damaged=%u\\n", (unsigned)g.v.count, g.v.violations[0].field_path, damaged);
    return damaged != 0 || g.v.count != 1 || strcmp(g.v.violations[0].field_path, "id") != 0;
}
'''

SMALL = ['-DPB_VALIDATE_MAX_PATH_DEPTH=1', '-DPB_VALIDATE_MAX_PATH_LENGTH=10']


class AbiCheckTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix='nanopb_ws_abi_')
        protos = os.path.join(cls.tmp, 'protos', 'demo')
        os.makedirs(protos)
        with open(os.path.join(protos, 'demo.proto'), 'w') as handle:
            handle.write(PROTO)
        cls.out = os.path.join(cls.tmp, 'out')
        status, _, err = run_backend('gen-c', '--protos-root', os.path.join(cls.tmp, 'protos'), '--out', cls.out,
                                     '--with-runtime', '--no-filter')
        assert status == 0, err
        cls.unit = os.path.join(cls.out, 'demo')
        with open(os.path.join(cls.unit, 'main.c'), 'w', newline='\n') as handle:
            handle.write(MAIN)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def build(self, tag, generated_flags, library_flags):
        cc = find_cc()
        if not cc:
            self.skipTest('no C compiler')
        objdir = os.path.join(self.tmp, 'obj_' + tag)
        os.makedirs(objdir)
        objects = []
        for name in sorted(os.listdir(self.unit)):
            if not name.endswith('.c'):
                continue
            flags = library_flags if name.startswith('pb_') else generated_flags
            obj = os.path.join(objdir, name + '.o')
            proc = subprocess.run(cc + ['-std=c99', '-O2', '-w'] + flags + ['-I', self.unit, '-c',
                                  os.path.join(self.unit, name), '-o', obj],
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
            self.assertEqual(proc.returncode, 0, proc.stdout)
            objects.append(obj)
        exe = os.path.join(objdir, 'abi' + ('.exe' if os.name == 'nt' else ''))
        link = subprocess.run(cc + ['-o', exe] + objects, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              universal_newlines=True)
        return link, exe

    def test_same_switches_link_and_run_clean(self):
        for tag, flags in (('default', []), ('small', SMALL)):
            link, exe = self.build(tag, flags, flags)
            self.assertEqual(link.returncode, 0, link.stdout)
            run = subprocess.run([exe], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
            self.assertEqual(run.returncode, 0, run.stdout)
            self.assertIn('damaged=0', run.stdout)

    def test_mismatched_switches_do_not_link(self):
        link, _ = self.build('mismatch', SMALL, [])
        self.assertNotEqual(link.returncode, 0, 'a mismatched build linked: it would corrupt memory')
        self.assertIn('_d1_l10_v16_m256_rel_f16', link.stdout)

    def test_debug_mismatch_does_not_link(self):
        link, _ = self.build('debug', ['-DPB_VALIDATE_DEBUG'], [])
        self.assertNotEqual(link.returncode, 0)
        self.assertIn('_dbg_f16', link.stdout)


if __name__ == '__main__':
    unittest.main()
