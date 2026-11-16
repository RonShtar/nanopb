"""validate/CMakeLists.txt: nanopb + validation built and installed the way nanopb is.

    cmake -S validate -B build; cmake --build build; cmake --install build

must put libprotobuf-nanopb-validate next to nanopb's own library and
pb_validate.h next to pb.h, and a project that does find_package(nanopb-validate)
must link against them and run. (nanopb's own CMakeLists installs only
pb.h, pb_common.h, pb_encode.h and pb_decode.h, and builds no validation library.)

Needs cmake and a generator (ninja) on PATH, and protoc where nanopb's CMakeLists
finds it; skipped without cmake. Toolchain options go in NANOPB_TEST_CMAKE_ARGS, on
Windows with zig from pip for example:

    -G Ninja -DCMAKE_C_COMPILER=C:/.../zig.exe -DCMAKE_C_COMPILER_ARG1=cc
    -DCMAKE_AR=C:/.../zigar.bat -DCMAKE_RANLIB=C:/.../zigranlib.bat
    -Dnanopb_PROTOC_PATH=C:/.../generator/protoc.bat
"""

import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest

from helpers import VALIDATE_DIR, run_backend

PROTO = '''syntax = "proto3";
package demo;
import "validate.proto";
message Ping { uint32 level = 1 [(validate.rules).uint32.lte = 5]; }
'''

MAIN = '''#include <stdio.h>
#include <pb_validate.h>
#include "demo.pb.h"
#include "demo_validate.h"

static int check(uint32_t level, unsigned *violations)
{
    pb_violations_t v;
    demo_Ping m = demo_Ping_init_zero;
    int ok;
    m.level = level;
    pb_violations_init(&v);
    ok = pb_validate_demo_Ping(&m, &v);
    *violations = (unsigned)v.count;
    return ok;
}

int main(void)
{
    unsigned n_good, n_bad;
    int good = check(3, &n_good), bad = check(9, &n_bad);
    printf("good=%d(%u) bad=%d(%u)\\n", good, n_good, bad, n_bad);
    return !(good && !bad && n_good == 0 && n_bad == 1);
}
'''

CONSUMER = '''cmake_minimum_required(VERSION 3.14)
project(consumer C)
find_package(nanopb-validate REQUIRED)
add_executable(consumer main.c ${GEN_DIR}/demo.pb.c ${GEN_DIR}/demo_validate.c)
target_include_directories(consumer PRIVATE ${GEN_DIR})
target_link_libraries(consumer nanopb::protobuf-nanopb-validate)
'''


def slash(path):
    return path.replace('\\', '/')


@unittest.skipUnless(shutil.which('cmake'), 'cmake is not on PATH')
class CMakeInstallTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='nanopb_cmake_install_')

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_step(self, argv):
        proc = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
        self.assertEqual(proc.returncode, 0, ' '.join(argv) + '\n' + proc.stdout[-3000:])
        return proc.stdout

    def write(self, directory, name, text):
        os.makedirs(directory, exist_ok=True)
        with open(os.path.join(directory, name), 'w', newline='\n') as handle:
            handle.write(text)

    def test_install_and_find_package(self):
        prefix = os.path.join(self.tmp, 'prefix')
        extra = shlex.split(os.environ.get('NANOPB_TEST_CMAKE_ARGS', ''), posix=os.name != 'nt')

        # nanopb's generator Python module goes into the prefix, not the real site-packages.
        build = os.path.join(self.tmp, 'build')
        self.run_step(['cmake', '-S', slash(VALIDATE_DIR), '-B', build,
                       '-DCMAKE_INSTALL_PREFIX=' + slash(prefix),
                       '-Dnanopb_PYTHON_INSTDIR_OVERRIDE=' + slash(os.path.join(prefix, 'pylib')),
                       '-DPython_EXECUTABLE=' + slash(sys.executable)] + extra)
        self.run_step(['cmake', '--build', build])
        self.run_step(['cmake', '--install', build])

        libs = os.listdir(os.path.join(prefix, 'lib'))
        self.assertTrue([n for n in libs if 'protobuf-nanopb-validate' in n], libs)
        self.assertTrue([n for n in libs if 'protobuf-nanopb' in n and 'validate' not in n], libs)
        include = os.path.join(prefix, 'include', 'nanopb')
        for header in ('pb.h', 'pb_validate.h', 'pb_filter_macros.h'):
            self.assertTrue(os.path.isfile(os.path.join(include, header)), header)
        config = os.path.join(prefix, 'lib', 'cmake', 'nanopb-validate', 'nanopb-validate-config.cmake')
        self.assertTrue(os.path.isfile(config))

        protos = os.path.join(self.tmp, 'protos')
        self.write(os.path.join(protos, 'demo'), 'demo.proto', PROTO)
        gen = os.path.join(self.tmp, 'gen')
        status, _, err = run_backend('gen-c', '--protos-root', protos, '--out', gen)
        self.assertEqual(status, 0, err)

        app = os.path.join(self.tmp, 'app')
        self.write(app, 'main.c', MAIN)
        self.write(app, 'CMakeLists.txt', CONSUMER)
        app_build = os.path.join(self.tmp, 'app_build')
        self.run_step(['cmake', '-S', app, '-B', app_build, '-DCMAKE_PREFIX_PATH=' + slash(prefix),
                       '-DGEN_DIR=' + slash(os.path.join(gen, 'demo'))] + extra)
        self.run_step(['cmake', '--build', app_build])
        exe = os.path.join(app_build, 'consumer' + ('.exe' if os.name == 'nt' else ''))
        self.assertIn('good=1(0) bad=0(1)', self.run_step([exe]))


if __name__ == '__main__':
    unittest.main()
