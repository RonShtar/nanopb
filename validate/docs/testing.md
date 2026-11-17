# Running all the tests

Four groups of tests. Run them in this order; each step says what it needs and what
a pass looks like. Commands are from the repository root (the folder with
`pb_decode.c`), written for Linux/macOS; the Windows differences are in section 6.

| # | What | Where | Runner |
|---|---|---|---|
| 1 | nanopb's own tests: the C runtime and nanopb's generator, unchanged | `tests/` | SCons |
| 2 | Our C tests: validators, packet filters, the validation runtime | `validate/tests/c/` | SCons |
| 3 | Our Python tests: tool, filters at run time, Wireshark plugins, security, performance, build files, the buf converter | `validate/tests/py/` | unittest / pytest |
| 4 | Optional: real Wireshark (`tshark`) | `validate/tests/py/test_tshark.py`, `live/` | with 3 |

Our files do not change nanopb's: test 3 includes `test_upstream_separation.py`, which
fails if any nanopb file differs from the commit named in `validate/UPSTREAM`. So step 1
measures upstream nanopb, and a failure there is not caused by this fork.

## 0. Set up once

```
python3 -m pip install protobuf grpcio-tools scons         # the generator and SCons
python3 -m pip install lupa pytest                         # Lua mock for the Wireshark plugin tests; pytest is optional
```

A C compiler (gcc or clang) is needed for 1, 2 and the C parts of 3. `cmake` and `ninja`
(`pip install cmake ninja` works) are needed for the CMake tests, which are skipped
without them. `valgrind` is used by step 1 where installed (Linux). `tshark` is only
for step 4.

## 1. nanopb's own tests

```
cd tests
scons                  # builds and runs every case; takes a few minutes
```

Pass: SCons ends with `scons: done building targets.` and no `scons: *** ... Error`
lines; each case prints `[ OK ]`. On macOS use `scons CC=clang CXX=clang++`. Flags that
are in `tests/SConstruct`: `NOVALGRIND=1` (skip valgrind), `NOUNSAFE=1` (skip tests that
break memory safety on purpose).

## 2. Our C tests

```
cd validate/tests/c
scons                  # do not use -j: the harness changes directory while it generates
```

or from anywhere: `python validate/nanopb_validate test --c` (extra SCons arguments can follow).
Pass: `scons: done building targets.` and `[ OK ]` for each program. Cases here:
validators for every rule type, `filter_any`, `filter_multi`, `filter_oneof`,
`filter_protocol` (the generated packet filter), imports, 64-bit limits, a benchmark.

## 3. Our Python tests

```
python validate/nanopb_validate test --py
# or:  cd validate/tests/py && python -m pytest -q
# only some:   python validate/nanopb_validate test --security      --perf
```

What is in it:

| File | Covers |
|---|---|
| `test_backend.py` | generation: merged C per protocol, rules, filters, `--compile-if`, `--first-include`, `--header-dir`, errors that must be clear |
| `test_filter_runtime.py` | the generated packet filter on real packets, built twice (stack and `PB_VALIDATE_FILTER_STATIC_BUFFERS`): `Any` in `Any`, in a oneof, in a sub-message, size and depth limits |
| `test_security.py` | fuzzing of every filter entry point, with guard pages and UBSan where the compiler has them |
| `test_performance.py` | time and size budgets of validators and filters |
| `test_stress.py` | the 7-file `fleet` example end to end: C round trip, samples, Wireshark dissection |
| `test_dissector.py` | the Lua plugins against a mock Wireshark (needs `lupa`, skipped without) |
| `test_cli.py` | `check`, `gen`, `packets`, `wireshark ...` as a user types them |
| `test_static_storage.py` | `Any.type_url` is exactly the longest URL + NUL (also from `any.in`, replacing a project value); no `pb_callback_t` or pointer field is generated: such a field is refused by name, `--allow-callbacks` allows it |
| `test_cmake_install.py` | `pb_validate` in nanopb's CMake build: `cmake -S validate` (3.14+) and the hook (3.19+) put it into `libprotobuf-nanopb.a` and a project linking only nanopb's library runs the validators; without either it is absent (control); `-DNANOPB_VALIDATE_IN_NANOPB_LIBRARY=OFF` builds a separate library that `find_package(nanopb-validate)` links |
| `test_build_addons.py` | `validate/extra/NanopbValidate.cmake` |
| `test_buf_convert.py` | `validate/tools/buf_to_validate.py` |
| `test_nanopb_api.py` | what this tool uses from nanopb is still there after an upgrade |
| `test_upstream_separation.py` | no nanopb file was changed |
| `test_tshark.py` | step 4 |

Pass: every test passes. Skips are normal and are printed: no `cmake`, no `lupa`, no
`tshark`, no compiler. A skip means that test did not run, not that it passed.

The CMake tests build two projects. Toolchain options go in an environment variable:

```
export NANOPB_TEST_CMAKE_ARGS="-G Ninja"                    # Windows with zig: section 6
python -m pytest -q validate/tests/py/test_cmake_install.py validate/tests/py/test_build_addons.py
# with another CMake, e.g. 3.18 (the hook test is then skipped):
NANOPB_TEST_CMAKE=/opt/cmake-3.18/bin/cmake python -m pytest -q validate/tests/py/test_cmake_install.py
```

`test_cmake_install.py` also needs `protoc` where nanopb's `CMakeLists.txt` finds it
(on PATH, or in `generator/` as `protoc`).

## 4. Real Wireshark (optional)

```
TSHARK=/path/to/tshark python -m pytest -q validate/tests/py/test_tshark.py
```

It dissects `validate/tests/py/live/` captures with the installed plugins and checks
the verdicts. `live/CHECKLIST.md` is the manual walk through the Wireshark menus.

## 5. All of it, in one go

```
(cd tests && scons) && (cd validate/tests/c && scons) && python validate/nanopb_validate test --py
```

## 6. Windows without gcc or MSVC

Use zig as the compiler (`pip install ziglang`) and let SCons believe it is gcc:

```
python -m pip install ziglang scons protobuf grpcio-tools lupa pytest cmake ninja
python validate\tests\windows_zig_shims.py C:\zigbin
set PATH=C:\zigbin;%PATH%
cd tests                 && python -m SCons BUILDDIR=build_zig       :: step 1
cd validate\tests\c      && python -m SCons BUILDDIR=build_zig       :: step 2
python validate\nanopb_validate test --py                            :: step 3
```

`windows_zig_shims.py` writes `gcc.bat`, `g++.bat`, `ar.bat`, `ranlib.bat` and
`mingw32-make.bat` (the last only so SCons picks its GNU toolchain). zig compiles with
clang, so the stand-in drops the GCC-only flags (`-Wlogical-op`, coverage) and relaxes
three clang-only warnings; everything else (`-Wall -Werror -ansi -pedantic`) is passed through.

For the CMake tests (also needs `protoc`: use nanopb's wrapper):

```
set NANOPB_TEST_CMAKE_ARGS=-G Ninja -DCMAKE_C_COMPILER=C:/.../ziglang/zig.exe -DCMAKE_C_COMPILER_ARG1=cc -DCMAKE_AR=C:/zigbin/ar.bat -DCMAKE_RANLIB=C:/zigbin/ranlib.bat -Dnanopb_PROTOC_PATH=C:/.../generator/protoc.bat
```

### What still fails on Windows with zig, and why

Step 1 on such a machine ends with failures that are the machine, not nanopb or this
fork. Measured on 2026-11-16: every case builds and passes except these 15 targets

| Targets | Reason |
|---|---|
| `cxx_callback_datatype` (4), `cxx_descriptor` (5): link of the C++ test programs | zig reports `unable to execute command: program not executable` linking them |
| `extra_fields` `*.equal` (2) | the comparison is textual; Windows writes `\r\n`, the expected file has `\n` (identical once CR is ignored) |
| `generator_relative_paths` (2), `regression/issue_494` | the test runs `python3`, which on Windows is the Microsoft Store stub |
| `proto3_optional` | the test's own command line has `"...bat"--experimental_allow_proto3_optional` with no space |

A full pass of step 1 needs Linux or macOS with gcc or clang (CI: `.github/workflows/`).

## 7. If something fails

* `unknown warning option` / `is a C99 extension` with zig: the shims are not first on
  `PATH`, so SCons is using something else.
* `Python was not found; run without arguments to install from the Microsoft Store`: a
  test calls `python3`; install Python from python.org and check `where python3`.
* `protoc compiler not found` from CMake: pass `-Dnanopb_PROTOC_PATH=` as above.
* nanopb's `CMakeLists.txt` on Windows with `-Dnanopb_PYTHON_INSTDIR_OVERRIDE=`: also
  pass `-DPython_EXECUTABLE=`; without it nanopb's own file fails at its `string(REPLACE ...)`
  on line 109 (the override skips the step that finds Python). `test_cmake_install.py` passes both.
* A failing C case after a change to `pb_validate.h`: generated code and the runtime
  must come from the same checkout; regenerate (`gen ... --with-runtime`).
