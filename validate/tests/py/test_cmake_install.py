"""pb_validate in nanopb's CMake build, built and installed the way nanopb is.

nanopb's own CMakeLists.txt builds libprotobuf-nanopb from pb_common.c, pb_encode.c and
pb_decode.c and installs four headers; it knows nothing of pb_validate. Two ways to add it
without changing a nanopb file, both tested here:

  project  cmake -S validate                                             (CMake 3.14+)
           pb_validate.c becomes part of nanopb's libprotobuf-nanopb.a itself;
           -DNANOPB_VALIDATE_IN_NANOPB_LIBRARY=OFF: a separate libprotobuf-nanopb-validate.a.
  hook     cmake -S . -DCMAKE_PROJECT_INCLUDE=validate/extra/nanopb_validate_hook.cmake (3.19+)
           the same as the project's default, from nanopb's own build.

Needs cmake and a generator (ninja) on PATH, and protoc where nanopb's CMakeLists finds it;
skipped without cmake. NANOPB_TEST_CMAKE=<path to cmake> picks another CMake (e.g. 3.18:
the hook test is then skipped). Toolchain options go in NANOPB_TEST_CMAKE_ARGS,
on Windows with zig from pip for example:

    -G Ninja -DCMAKE_C_COMPILER=C:/.../zig.exe -DCMAKE_C_COMPILER_ARG1=cc
    -DCMAKE_AR=C:/.../zigar.bat -DCMAKE_RANLIB=C:/.../zigranlib.bat
    -Dnanopb_PROTOC_PATH=C:/.../generator/protoc.bat
"""

import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest

from helpers import REPO_ROOT, VALIDATE_DIR, run_backend

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
find_package(${PKG} REQUIRED)
add_executable(consumer main.c ${GEN_DIR}/demo.pb.c ${GEN_DIR}/demo_validate.c)
target_include_directories(consumer PRIVATE ${GEN_DIR})
target_link_libraries(consumer ${LIB})
'''

HOOK = os.path.join(VALIDATE_DIR, 'extra', 'nanopb_validate_hook.cmake')
CMAKE = os.environ.get('NANOPB_TEST_CMAKE') or shutil.which('cmake')


def cmake_version():
    out = subprocess.run([CMAKE, '--version'], stdout=subprocess.PIPE, universal_newlines=True).stdout
    match = re.search(r'(\d+)\.(\d+)', out)
    return (int(match.group(1)), int(match.group(2))) if match else (0, 0)


def slash(path):
    return path.replace('\\', '/')


@unittest.skipUnless(CMAKE, 'cmake is not on PATH')
class CMakeInstallTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='nanopb_cmake_install_')
        self.extra = shlex.split(os.environ.get('NANOPB_TEST_CMAKE_ARGS', ''), posix=os.name != 'nt')

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_step(self, argv):
        if argv[0] == 'cmake':
            argv = [CMAKE] + argv[1:]
        proc = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
        self.assertEqual(proc.returncode, 0, ' '.join(argv) + '\n' + proc.stdout[-3000:])
        return proc.stdout

    def write(self, directory, name, text):
        os.makedirs(directory, exist_ok=True)
        with open(os.path.join(directory, name), 'w', newline='\n') as handle:
            handle.write(text)

    def build_and_install(self, source, *options):
        """Configure, build and install `source`; returns the install prefix."""
        prefix = os.path.join(self.tmp, 'prefix')
        build = os.path.join(self.tmp, 'build')
        # nanopb's generator Python module goes into the prefix, not the real site-packages.
        self.run_step(['cmake', '-S', slash(source), '-B', build, '-DCMAKE_INSTALL_PREFIX=' + slash(prefix),
                       '-Dnanopb_PYTHON_INSTDIR_OVERRIDE=' + slash(os.path.join(prefix, 'pylib')),
                       '-DPython_EXECUTABLE=' + slash(sys.executable)] + list(options) + self.extra)
        self.run_step(['cmake', '--build', build])
        self.run_step(['cmake', '--install', build])
        return prefix

    def consume(self, prefix, package, library):
        """A project that links `library` from find_package(`package`) and calls the validators."""
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
                       '-DPKG=' + package, '-DLIB=' + library,
                       '-DGEN_DIR=' + slash(os.path.join(gen, 'demo'))] + self.extra)
        self.run_step(['cmake', '--build', app_build])
        exe = os.path.join(app_build, 'consumer' + ('.exe' if os.name == 'nt' else ''))
        self.assertIn('good=1(0) bad=0(1)', self.run_step([exe]))

    def check_headers(self, prefix):
        include = os.path.join(prefix, 'include', 'nanopb')
        for header in ('pb.h', 'pb_validate.h', 'pb_filter_macros.h'):
            self.assertTrue(os.path.isfile(os.path.join(include, header)), header)

    def check_in_nanopb_library(self, prefix):
        """One library, nanopb's, holding the runtime and pb_validate; a project linking only
        nanopb's library runs the validators."""
        libs = [n for n in os.listdir(os.path.join(prefix, 'lib')) if 'protobuf-nanopb' in n]
        self.assertEqual(len(libs), 1, libs)                     # one library, not a second one
        with open(os.path.join(prefix, 'lib', libs[0]), 'rb') as handle:
            archive = handle.read()
        for symbol in (b'pb_encode', b'pb_decode', b'pb_violations_init', b'pb_validate_int32'):
            self.assertIn(symbol, archive, symbol)
        self.check_headers(prefix)
        self.consume(prefix, 'nanopb', 'nanopb::protobuf-nanopb-static')

    def test_project_puts_pb_validate_into_nanopbs_own_library(self):
        """cmake -S validate (CMake 3.14+): nanopb built from its unchanged root, pb_validate.c
        added to its library after add_subdirectory."""
        self.check_in_nanopb_library(self.build_and_install(VALIDATE_DIR))

    def test_hook_puts_pb_validate_into_nanopbs_own_library(self):
        """cmake -S . with the hook (CMake 3.19+): the same, from nanopb's own build."""
        if cmake_version() < (3, 19):
            self.skipTest('the hook needs CMake 3.19 (cmake_language(DEFER))')
        self.check_in_nanopb_library(self.build_and_install(REPO_ROOT, '-DCMAKE_PROJECT_INCLUDE=' + slash(HOOK)))

    def test_plain_nanopb_build_has_no_validation(self):
        """The control: without the hook nanopb's library has no pb_validate (the reason for it)."""
        prefix = self.build_and_install(REPO_ROOT)
        libs = [n for n in os.listdir(os.path.join(prefix, 'lib')) if 'protobuf-nanopb' in n]
        with open(os.path.join(prefix, 'lib', libs[0]), 'rb') as handle:
            self.assertNotIn(b'pb_violations_init', handle.read())
        self.assertFalse(os.path.exists(os.path.join(prefix, 'include', 'nanopb', 'pb_validate.h')))

    def test_project_builds_a_separate_library(self):
        """cmake -S validate -DNANOPB_VALIDATE_IN_NANOPB_LIBRARY=OFF: libprotobuf-nanopb-validate
        next to nanopb's library."""
        prefix = self.build_and_install(VALIDATE_DIR, '-DNANOPB_VALIDATE_IN_NANOPB_LIBRARY=OFF')
        libs = os.listdir(os.path.join(prefix, 'lib'))
        self.assertTrue([n for n in libs if 'protobuf-nanopb-validate' in n], libs)
        self.assertTrue([n for n in libs if 'protobuf-nanopb' in n and 'validate' not in n], libs)
        self.check_headers(prefix)
        self.assertTrue(os.path.isfile(os.path.join(prefix, 'lib', 'cmake', 'nanopb-validate',
                                                    'nanopb-validate-config.cmake')))
        self.consume(prefix, 'nanopb-validate', 'nanopb::protobuf-nanopb-validate')


if __name__ == '__main__':
    unittest.main()
