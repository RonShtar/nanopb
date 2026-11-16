#!/usr/bin/env python3
"""Windows without gcc or MSVC: gcc, g++, ar, ranlib and mingw32-make on top of zig.

    python -m pip install ziglang
    python validate/tests/windows_zig_shims.py C:\\zigbin          # any empty folder
    set PATH=C:\\zigbin;%PATH%
    cd tests && python -m SCons BUILDDIR=build_zig                # nanopb's own suite
    cd validate\\tests\\c && python -m SCons BUILDDIR=build_zig   # ours

SCons picks its GNU toolchain when it finds mingw32-make on PATH, and then calls
gcc/g++/ar. zig's compiler is clang, which rejects a few GCC-only flags and is
stricter than GCC about a few others, so the stand-in drops or relaxes exactly
these and passes everything else (-Wall -Werror -ansi -pedantic ...) through:

    dropped:    -Wlogical-op -fprofile-arcs -ftest-coverage --coverage -lgcov   (GCC only)
    relaxed:    -Wno-c99-extensions -Wno-c11-extensions -Wno-strict-prototypes
                (clang warns about bool/_Static_assert/f() where GCC does not)

On such a machine nanopb's own suite still has failures that are the machine, not
nanopb: tests that call python3 (the Microsoft Store stub), C++ link steps zig cannot
do, text comparisons that see CRLF, and one test whose own command line lacks a space.
docs/testing.md lists them. Run the suite on Linux/macOS with gcc or clang for a
complete result.
"""

import os
import sys

WRAPPER = '''"""gcc/g++ stand-in on top of zig (written by windows_zig_shims.py)."""
import subprocess
import sys

DROP = {'-Wlogical-op', '-fprofile-arcs', '-ftest-coverage', '--coverage', '-lgcov'}
RELAX = ['-Wno-c99-extensions', '-Wno-c11-extensions', '-Wno-strict-prototypes']
mode = sys.argv[1]
args = [a for a in sys.argv[2:] if a not in DROP]
if mode in ('cc', 'c++'):
    args += RELAX
sys.exit(subprocess.call([sys.executable, '-m', 'ziglang', mode] + args))
'''

SHIMS = {'gcc': 'cc', 'g++': 'c++', 'ar': 'ar', 'ranlib': 'ranlib'}


def main(argv):
    if len(argv) != 2 or argv[1] in ('-h', '--help'):
        sys.stdout.write(__doc__)
        return 0 if len(argv) == 2 else 1
    folder = os.path.abspath(argv[1])
    if os.path.exists(folder) and os.listdir(folder):
        sys.stderr.write('error: %s is not empty; give a new folder\n' % folder)
        return 1
    try:
        import ziglang  # noqa: F401
    except ImportError:
        sys.stderr.write('error: pip install ziglang first\n')
        return 1
    os.makedirs(folder, exist_ok=True)
    wrapper = os.path.join(folder, 'zigwrap.py')
    with open(wrapper, 'w', newline='\n') as handle:
        handle.write(WRAPPER)
    for name, mode in SHIMS.items():
        with open(os.path.join(folder, name + '.bat'), 'w', newline='\r\n') as handle:
            handle.write('@"%s" "%s" %s %%*\n' % (sys.executable, wrapper, mode))
    with open(os.path.join(folder, 'mingw32-make.bat'), 'w', newline='\r\n') as handle:
        handle.write('@echo zig shim: only here so that SCons selects its GNU toolchain\n')
    sys.stdout.write('wrote %s\nnext:  set PATH=%s;%%PATH%%\n' % (folder, folder))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
