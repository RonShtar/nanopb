# nanopb validate

Validation, packet filters and Wireshark tools for [nanopb](../README.md).

- **Validators.** `validate.proto` rules in your `.proto` files become C
  functions with no heap and no reflection: `<protocol>_validate_<message>()` for a protocol
  folder (`fleet_validate_cmd_Move()`), `pb_validate_<Message>()` for single `.proto` files.
- **Packet filters.** `<protocol>_udp()` / `_tcp()` decode, identify and
  validate an untrusted packet and return 0 (accept) or -1 (drop, logged).
- **Wireshark.** A dissector that decodes nested messages and
  `google.protobuf.Any`, shows PASSED / DROPPED per packet, and a Tools menu
  that drives everything below.
- **Test data.** Captures and C arrays of valid and invalid packets for every
  message.

Everything lives in this `validate/` folder. nanopb's own files are untouched
(the tests check it), so upgrading nanopb stays a plain merge; see
[Upgrading nanopb](#upgrading-nanopb).

## Quick start

    python -m pip install protobuf grpcio-tools            # once, same as nanopb
    cd validate

    python -m nanopb_validate check   path/to/protos                   # syntax, rules, storage, filters
    python -m nanopb_validate gen     path/to/protos --out out         # C per protocol
    python -m nanopb_validate packets path/to/protos --out out         # test capture + C arrays
    python -m nanopb_validate wireshark install --protos-root path/to/protos

`path/to/protos` has one folder per protocol. A protocol's `.proto` files may
sit in folders of their own (`protocol_A/messages/`, `protocol_A/enums/`); its
imports may be relative to the importing file, the protocol folder or the
protos directory. From the nanopb checkout, `python validate/nanopb_validate ...`
works the same.

## Commands

| Command | What it does |
|---|---|
| `check PROTOS_DIR` | Compiles every protocol and reports errors (syntax, imports, rules the generator cannot honour, fields without `max_size`/`max_count`: they would be `pb_callback_t`) and warnings (messages needing `PB_FIELD_32BIT`, filters that cannot be built). Exit 1 on errors. |
| `gen PROTOS_DIR --out DIR` | Per protocol: one merged `<p>.pb.c/.h` (messages, descriptors, packet filters) and `<p>_validate.c/.h`. `--with-runtime` also copies the C runtime; `--filter-name NAME` names the protocol filter `NAME_udp/_tcp` (default `{unit}` = protocol folder); `--compile-if CONFIG_COMPILE_FILTER` wraps every generated `.c` and `.h` in `#ifdef CONFIG_COMPILE_FILTER ... #endif`, so they compile only when your build defines it; `--first-include FILE` puts `#include "FILE"` at the top of every file, before that `#ifdef`; `--header-dir filter/{unit}` makes the generated files include each other as `"filter/camera/camera_validate.h"`; `--include-prefix NanoPB` makes the generated C include `<NanoPB/pb.h>` (the runtime then goes to `<out>/<p>/NanoPB/`). Imports from outside a protocol folder get that protocol's prefix, so all protocols link into one program; with several protocols and `--with-runtime` the runtime goes once to `<out>/common/`. |
| `gen FILE.proto ...` | Per file, like nanopb: `<f>.pb.c/.h` and `<f>_validate.c/.h`. `--filter pkg.Msg` adds a filter; `--nanopb-opt` passes nanopb options to both generators. |
| `packets PROTOS_DIR --out DIR` | A capture of PASSED and DROPPED packets of every message, plus each packet as a C array and hex; installs the dissector schema. |
| `wireshark install` | Installs the Lua plugins and a private copy of this tool into Wireshark (once). |
| `wireshark load` / `refresh` | Loads a protos directory into the dissector now / rebuilds it if protos changed (the dissector runs `refresh` at startup). |
| `test [--py] [--c] [--perf] [--security]` | Runs the tests below. |

Every command takes `--help`. Directory commands print a JSON result (the
Wireshark plugins read it) ending in `__EXIT__=<status>`.

## Using the generated C

Compile the generated files with nanopb's runtime (`pb_encode.c`,
`pb_decode.c`, `pb_common.c`) and `runtime/pb_validate.c`, with `-I` for the
nanopb root and `validate/runtime`. C99 is required (`bool`, `inline`); the
generated code itself keeps C89 declaration style.

```c
#define PB_VALIDATE_FILTER_LOG(...) printf(__VA_ARGS__)   /* optional: see drops */
#include "fleet.pb.h"

if (fleet_udp(NULL, data, size) != 0)
    return;                     /* dropped; one log line says why */
```

- Every drop calls `PB_VALIDATE_FILTER_DROP(filter, reason)` in every build; it hands
  `PB_VALIDATE_FILTER_LOG` one ready-made string, so a one-argument logger works too
  (`#define PB_VALIDATE_FILTER_LOG(line) my_log(line)`). `PB_VALIDATE_DEBUG` builds also
  log each violated rule through `PB_VALIDATE_FILTER_RULE(reason, path, rule_id, message)`.
- Several protocols in one program: compile each `<out>/<protocol>/*.c` and the nanopb
  runtime once (`<out>/common/` when they were generated together with `--with-runtime`).
- Use `pb_validate.c/.h` from the same checkout as the generator: generated code stops with
  `#error "pb_validate.h is older than this generated code"` otherwise.
- One filter per protocol, named after its folder: `<protocol>_udp/_tcp` accepts any message of the
  protocol (by its `Any` type_url); a protocol without `Any` gets one filter for its
  root message, under the same name.
- Imports from outside the protocol folder (`google/protobuf/*`, shared protos) get the
  protocol's prefix (`camera_google_protobuf_Any`), so protocols never clash, even
  when generated separately.
- Every generated file starts with a Doxygen block (`@file`, `@brief`, `@date`,
  `@author`; `gen --author "Name"` or the Wireshark dialog sets the author).
- Keep nanopb in its own folder: `gen --include-prefix NanoPB` (or the
  Wireshark menu's include field, or `wireshark install --include-prefix NanoPB`)
  writes `#include <NanoPB/pb.h>`, `<NanoPB/pb_validate.h>`, ...; compile with `-I`
  on the folder that contains `NanoPB/`.
- Match your project's tree:
  `gen --header-dir "filter/{unit}" --first-include filter_source_include.h --compile-if CONFIG_COMPILE_FILTER`
  makes every generated `.c` and `.h` start with
  `#include "filter_source_include.h"` (your header, the one that may define
  `CONFIG_COMPILE_FILTER`), then `#ifdef CONFIG_COMPILE_FILTER ... #endif /* CONFIG_COMPILE_FILTER */`
  around the rest of the file, and the generated files include each other as
  `#include "filter/camera/camera_validate.h"`. If the build does not define
  `CONFIG_COMPILE_FILTER` the files compile to nothing. In Wireshark these are three fields of
  Tools > nanopb > Set protos directory, saved for every Generate C; `wireshark install`
  takes the same options only to pre-fill them. Nothing else needs them.
- Static storage only, no callbacks, no malloc: `gen` refuses a protocol in which any field
  would be a `pb_callback_t` (string, bytes, repeated or map without `max_size`/`max_count`)
  or a pointer, and names each field; `--allow-callbacks` turns that off.
- `google.protobuf.Any` is static and sized per protocol, `gen` prints both: `type_url` is exactly
  the longest URL it can carry (`type.googleapis.com/` + the longest message name, or a longer
  `any.in` URL, + NUL); `value` is the largest maximum size nanopb computes (`#define <msg>_size`)
  of any message of the protocol, with the `Any`s inside it holding the largest message that has
  none: every message with one level of `Any` (a `Packet { Any payload }` holding a `Frame`) always
  fits. Where an `Any` may hold a message that carries an `Any` itself (no `any.in`, or one that
  allows such a message) `gen`/`check` warn and name the field: deeper nesting fits only when
  that small; `--any-value-size N` sets the size (a field of Set protos directory in Wireshark).
  `.options` values for `Any` are replaced.
- `<PROTOCOL>_MAX_SIZE` in `<protocol>.pb.h`: the largest packet (nanopb's `_size` of the `Any`,
  or of the largest message without one), for receive buffers.
  See [docs/any-examples.md](docs/any-examples.md) for a 7-file protocol that uses `Any` in
  repeated fields, oneofs, sub-messages and inside other `Any`s, merged into one `.c`.
- `--protos-root` is the folder *above* the protocol folders (`protocols/`, holding
  `camera/`, `gps/`, ...). Pointing it at one protocol's folder makes that the only protocol.
- Define `PB_FIELD_32BIT` (and any other `PB_*` switch) identically for every
  file, nanopb's included; `check` and `gen` tell you when it is needed.

Rules, options and every switch: [docs/validation.md](docs/validation.md).
Cost per packet, stack and the switches that change them:
[docs/performance.md](docs/performance.md).

### Build systems

| | |
|---|---|
| CMake 3.14+, `pb_validate` inside nanopb's own library | `cmake -S validate -B build && cmake --build build && cmake --install build`. This builds nanopb from the repository root with nanopb's `CMakeLists.txt` unchanged, then adds `validate/runtime/pb_validate.c` to nanopb's `libprotobuf-nanopb` (so `pb_validate.o` is a member of the same `.a`) and installs `pb_validate.h` and `pb_filter_macros.h` next to `pb.h`. Use it as nanopb: `find_package(nanopb)`, link `nanopb::protobuf-nanopb-static`. Tested with CMake 3.18. (nanopb's own build alone has no `pb_validate`: it compiles only `pb_common`, `pb_encode`, `pb_decode`.) |
| CMake 3.19+, the same from nanopb's own build | `cmake -S . -B build -DCMAKE_PROJECT_INCLUDE=validate/extra/nanopb_validate_hook.cmake`, then build and install as usual: the same result as the line above, for builds that must start at nanopb's root. Stops with a clear message on CMake 3.18 and older. |
| CMake 3.14+, separate validation library | `cmake -S validate -B build -DNANOPB_VALIDATE_IN_NANOPB_LIBRARY=OFF`: nanopb as usual **and** a separate `libprotobuf-nanopb-validate`, with `find_package(nanopb-validate)` and `nanopb::protobuf-nanopb-validate` (it links the nanopb runtime too). `-DNANOPB_VALIDATE_WITH_NANOPB=OFF` adds only that library to an installed nanopb. |
| CMake, generate | `include(validate/extra/NanopbValidate.cmake)` after `find_package(Nanopb)`, then `nanopb_validate_generate(SRCS HDRS a.proto [OPTIONS --filter pkg.Msg])` and link `nanopb_validate`. |
| make | `include validate/extra/nanopb_validate.mk` (before nanopb's `extra/nanopb.mk`); `%.proto` builds `.pb.c/.h` and `_validate.c/.h`. |
| protoc | `--plugin=protoc-gen-nanopb-validate=validate/nanopb_validate/plugin/protoc-gen-nanopb-validate`, `--nanopb_out` before `--nanopb-validate_out`; see [docs/validation.md](docs/validation.md#with-protoc-directly). |

The add-ons run `gen`, which the tests cover. The CMake files are built and run
by `test_cmake_install.py` and `test_build_addons.py` (skipped where `cmake` is
missing); the make file is not exercised by the tests.

## Layout

```
validate/
  README.md            this file
  UPSTREAM             the nanopb commit this tree is based on
  runtime/             pb_validate.c/.h, pb_filter_macros.h (C runtime)
  nanopb_validate/     Python package: python -m nanopb_validate
    cli.py             the commands above
    backend.py         engine entry point (command parser) behind cli.py
    protos.py          protocols of a protos directory, nested folders, descriptors
    gen.py             merged C per protocol, PB_FIELD_32BIT hints
    traffic.py         sample messages, captures (pcap/pcapng), C arrays
    wireshark.py       dissector schema, install / load / refresh
    rule_model.py      validate.proto rules -> validation model (per field / message)
    emitters.py        C code per rule type
    validator.py       writes <name>_validate.c/.h from the model
    c_layout.py        generated-C layout (C89 blocks) and #include format
    filters.py         protoc plugin entry: validators + packet filters
    filter_*.py        filter model, options, analyzer (dispatch), C emission
    datagen.py         DataGenerator: valid / invalid sample messages (+ CLI)
    schema.py          descriptors, .options limits, field/message info for datagen
    values.py, containers.py, violations.py, encoding.py   DataGenerator parts
    env.py             paths; uses nanopb's generator read-only
    plugin/            protoc-gen-nanopb-validate launchers
    validate_proto/    validate.proto (+ any/timestamp)
  wireshark/           Lua dissector and Tools > nanopb menu
  CMakeLists.txt       cmake -S validate: nanopb + libprotobuf-nanopb-validate, installed
  extra/               CMake and make add-ons, find_package(nanopb-validate) config
  tools/               buf_to_validate.py: buf.validate -> validate.rules (standalone, stdlib only)
  examples/stress/     a full protocol: protos, captures, C round trip
  tests/py/            tool, filters at run time, dissector, CLI, security, performance, build files, separation
  tests/c/             C tests of the runtime and generated code (SCons)
  tests/windows_zig_shims.py   gcc/ar stand-ins on zig for Windows without gcc or MSVC
  docs/                validation, performance, Any examples, testing, Wireshark guide and reference, data generator
```

## Tests

    python -m nanopb_validate test --py          # ~2 minutes
    python -m nanopb_validate test --c           # SCons; on Windows without MSVC add TOOLS=mingw CC=... (zig/clang)
    python -m nanopb_validate test --security    # fuzz every filter: guard pages + UBSan
    python -m nanopb_validate test --perf        # budgets: filter <= 1.25 x decode, stack, context size

`tests/py/test_upstream_separation.py` fails if any nanopb file differs from
`UPSTREAM`. All four groups of tests, nanopb's own included, step by step:
[docs/testing.md](docs/testing.md).

### Converting protovalidate (buf.validate) protos

`tools/buf_to_validate.py` is a separate script, not part of the generator:

    python validate/tools/buf_to_validate.py PROTOS --out CONVERTED

It rewrites `(buf.validate.field)` options to `(validate.rules)`, keeps comments, never
touches the input, and lists every rule nanopb-validate cannot enforce (CEL,
`pattern`, ...) instead of converting it into something that only looks equivalent.

## Upgrading nanopb

    git fetch upstream
    git merge upstream/master                   # nanopb files are untouched: no conflicts
    git rev-parse upstream/master > validate/UPSTREAM
    python -m nanopb_validate test

Only additions live outside this folder (`CLAUDE.md`, `agent_docs/`,
`.claude/`) plus one block at the end of `.gitignore`.

Everything this tool uses from nanopb (generator functions, options, files)
is listed in `nanopb_validate/nanopb_api.py`, and no other module imports
nanopb. After a merge, `check` and `tests/py/test_nanopb_api.py` say whether
anything moved; a fix goes in `nanopb_api.py`, never in nanopb's files.

## More

- [docs/validation.md](docs/validation.md): rules, options, filters, drop logs, `PB_*` switches
- [docs/performance.md](docs/performance.md): measured cost, stack, what each switch costs
- [docs/wireshark.md](docs/wireshark.md): Wireshark guide, step by step
- [docs/wireshark-reference.md](docs/wireshark-reference.md): menu, dissector and command reference
- [docs/datagen.md](docs/datagen.md): the test data generator
- [docs/any-examples.md](docs/any-examples.md): `google.protobuf.Any` with many protos, static storage, the generated filter
- [docs/testing.md](docs/testing.md): running all the tests, step by step
