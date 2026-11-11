"""Build-system add-ons: validate/extra/NanopbValidate.cmake end to end.

Configures a small project with nanopb's FindNanopb plus our add-on, builds
it and runs it: the generated filter must accept a valid packet and drop an
invalid one. Needs cmake (and a generator, e.g. ninja) on PATH; skipped
otherwise. Toolchain options go in NANOPB_TEST_CMAKE_ARGS, for example on
Windows with zig from pip:

    NANOPB_TEST_CMAKE_ARGS="-G Ninja -DCMAKE_C_COMPILER=C:/.../zig.exe -DCMAKE_C_COMPILER_ARG1=cc -DCMAKE_AR=C:/.../zigar.bat"
"""

import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest

from helpers import REPO_ROOT

PROTO = '''syntax = "proto3";
package demo;
import "validate.proto";
message Ping { uint32 level = 1 [(validate.rules).uint32.lte = 5]; }
'''

MAIN = '''#include <stdio.h>
#include <pb_encode.h>
#include "demo.pb.h"
#include "demo_validate.h"

static int send(uint32_t level)
{
    uint8_t buf[16];
    pb_ostream_t s = pb_ostream_from_buffer(buf, sizeof buf);
    demo_Ping m = demo_Ping_init_zero;
    m.level = level;
    if (!pb_encode(&s, demo_Ping_fields, &m)) return 99;
    return demo_Ping_filter_udp(NULL, buf, s.bytes_written);
}

int main(void)
{
    int good = send(3), bad = send(9);
    printf("good=%d bad=%d\\n", good, bad);
    return !(good == 0 && bad == -1);
}
'''

CMAKELISTS = '''cmake_minimum_required(VERSION 3.14)
project(addon_demo C)
list(APPEND CMAKE_MODULE_PATH ${NANOPB_DIR}/extra)
find_package(Nanopb REQUIRED)
include(${NANOPB_DIR}/validate/extra/NanopbValidate.cmake)
nanopb_validate_generate(SRCS HDRS demo.proto OPTIONS --filter demo.Ping)
add_executable(demo main.c ${SRCS} ${HDRS} ${NANOPB_SRCS})
target_include_directories(demo PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${NANOPB_INCLUDE_DIRS})
target_link_libraries(demo nanopb_validate)
'''


@unittest.skipUnless(shutil.which('cmake'), 'cmake is not on PATH')
class CMakeAddonTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='nanopb_cmake_')

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_step(self, argv):
        proc = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
        self.assertEqual(proc.returncode, 0, ' '.join(argv) + '\n' + proc.stdout[-3000:])
        return proc.stdout

    def test_generate_build_and_run(self):
        for name, text in (('demo.proto', PROTO), ('main.c', MAIN), ('CMakeLists.txt', CMAKELISTS)):
            with open(os.path.join(self.tmp, name), 'w') as handle:
                handle.write(text)
        build = os.path.join(self.tmp, 'build')
        extra = shlex.split(os.environ.get('NANOPB_TEST_CMAKE_ARGS', ''), posix=os.name != 'nt')
        self.run_step(['cmake', '-S', self.tmp, '-B', build, '-DNANOPB_DIR=' + REPO_ROOT.replace('\\', '/'),
                       '-DPython3_EXECUTABLE=' + sys.executable.replace('\\', '/')] + extra)
        self.run_step(['cmake', '--build', build])
        exe = os.path.join(build, 'demo' + ('.exe' if os.name == 'nt' else ''))
        self.assertIn('good=0 bad=-1', self.run_step([exe]))


if __name__ == '__main__':
    unittest.main()
