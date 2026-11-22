# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

Nanopb: a small protobuf runtime in portable C (`pb_common.c`, `pb_encode.c`, `pb_decode.c`, optional `pb_validate.c`) plus a Python generator (`generator/nanopb_generator.py`) that turns `.proto` files into C structs and descriptors. Paths below are relative to the repo root; authoritative user/API docs live in `docs/`.

## Where to look first

- Runtime bug or feature: `pb.h` (configuration macros; changes there ripple into many tests and integrations) plus the relevant `pb_*.c`
- Generator bug or generated-code shape: `generator/nanopb_generator.py` and the nearest case in `tests/`
- Validation: `pb_validate.*`, `generator/nanopb_validator.py`, `generator/nanopb_validate_generator.py`, `tests/validation/`, `examples/validation_simple/`
- Build-system integration: `CMakeLists.txt`, `meson.build`, `BUILD.bazel`, `Package.swift`, or `extra/`

## C language rules

- The core runtime (`pb_common`, `pb_encode`, `pb_decode`) must compile as C89 under `-ansi -pedantic -Wconversion -Wcast-qual -Werror`: no `//` comments, no declarations after statements, no `inline`, explicit casts on narrowing conversions.
- Only `pb_validate.*` and generated `*_validate.*` may use C99 (`static inline`); `tests/validation/SConscript` swaps `-ansi` for `-std=c99` for those builds.

## Code generation

- Deps: `python -m pip install protobuf grpcio-tools`, plus `protoc` on PATH (`CMakeLists.txt` fails immediately without it).
- Plain output: `python generator/nanopb_generator.py your_file.proto`
- Validation output needs nanopb run with `--nanopb_opt=--protoc-insertion-points`, then `--nanopb-validate_out=.` placed after `--nanopb_out` (see `examples/validation_simple/Makefile`). In SCons, set `NANOPB_VALIDATE_FLAGS` to a non-None value and `NANOPBFLAGS="-x,validate.proto"`.
- An unsupported validate rule (e.g. `string.pattern`) is a hard generator error by design; `tests/validation/unimplemented_rules_check.py` enforces this.
- The pip package (`extra/poetry/pyproject.toml`) does not ship the `protoc-gen-nanopb-validate` plugin.
- Generated `*.pb.[ch]` and `*_validate.[ch]` files are gitignored; never commit them.

## Tests

- Default verification for any runtime or generator change: `cd tests && scons`. There is no separate lint step; strict warnings-as-errors in `tests/SConstruct`, plus valgrind when it's on PATH, are the quality gate.
- Delete `tests/build` when switching `CC`, `CCFLAGS` or `PLATFORM`; CI does this between variants.
- Useful SCons vars: `CC`, `CXX`, `CCFLAGS`, `LINKFLAGS`, `BUILDDIR`, `PLATFORM=AVR|MIPS|MIPSEL|RISCV64`, `NOVALGRIND=1`.
- On-push CI runs only plain `scons`. The compiler variants (`-O3`, `-Os -flto`, `-DPB_FIELD_32BIT=1`, `-m32`, clang) and the simulator platforms run weekly (`.github/workflows/trigger_on_schedule.yml`).
- Windows: run SCons as `python -m SCons` and pass `PYTHON=python`, because `python3` may resolve to the WindowsApps stub. Without `CC`, SCons picks MSVC.
- If you change integration files, run only the matching check:
  - CMake: `cmake -S . -B build && cmake --build build`
  - Meson: `meson setup build -Dexamples=enabled && ninja -C build`
  - Bazel: `bazelisk test --//:nanopb_extension=.pb //...`; CI also runs `.nanopb`
  - SwiftPM: `swift build && swift test`
  - PlatformIO: follow `.github/workflows/platformio_tests.yml`

## Fork workflow

- Remotes:
  - `origin` = OfekiAlm/nanopb (PR target)
  - `fork` = RonShtar/nanopb (push topic branches here)
  - `upstream` = nanopb/nanopb
- Upstream changes come in through merge commits ("Merge branch 'nanopb:master' into master"), never rebases.

## Read more only when needed

- `agent_docs/architecture.md`: runtime/generator split, validation layers, design tradeoffs
- `agent_docs/building.md` and `agent_docs/testing.md`: per-build-system commands and which tests to run for which change
- `docs/reference.md`, `docs/concepts.md`, `docs/validation.md`: public API, protocol mapping, validation behavior
