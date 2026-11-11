# nanopb validate

Validation, packet filters and Wireshark tools for [nanopb](../README.md).

- **Validators.** `validate.proto` rules in your `.proto` files become C
  functions, `pb_validate_<Message>()`, with no heap and no reflection.
- **Packet filters.** `<protocol>_filter_udp()` / `_tcp()` decode, identify and
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
| `check PROTOS_DIR` | Compiles every protocol and reports errors (syntax, imports, rules the generator cannot honour) and warnings (fields without `max_size`/`max_count`, messages needing `PB_FIELD_32BIT`, filters that cannot be built). Exit 1 on errors. |
| `gen PROTOS_DIR --out DIR` | Per protocol: one merged `<p>.pb.c/.h` (messages, descriptors, packet filters) and `<p>_validate.c/.h`. `--with-runtime` also copies the C runtime; `--filter-name NAME` names the protocol filter `NAME_udp/_tcp` (`{unit}` = protocol folder); `--include-prefix NanoPB` makes the generated C include `<NanoPB/pb.h>` (the runtime then goes to `<out>/<p>/NanoPB/`). |
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

if (fleet_filter_udp(NULL, data, size) != 0)
    return;                     /* dropped; one log line says why */
```

- Every drop calls `PB_VALIDATE_FILTER_DROP(filter, reason)` in every build;
  `PB_VALIDATE_DEBUG` builds also log each violated rule.
- One filter per protocol: `<protocol>_filter_udp/_tcp` accepts any message of the
  protocol (by its `Any` type_url); a protocol without `Any` gets one filter for its
  root message, `<pkg>_<Msg>_filter_udp/_tcp`.
- Every generated file starts with a Doxygen block (`@file`, `@brief`, `@date`,
  `@author`; `gen --author "Name"` or the Wireshark dialog sets the author).
- Keep nanopb in its own folder: `gen --include-prefix NanoPB` (or the
  Wireshark menu's include field, or `wireshark install --include-prefix NanoPB`)
  writes `#include <NanoPB/pb.h>`, `<NanoPB/pb_validate.h>`, ...; compile with `-I`
  on the folder that contains `NanoPB/`.
- Define `PB_FIELD_32BIT` (and any other `PB_*` switch) identically for every
  file, nanopb's included; `check` and `gen` tell you when it is needed.

Rules, options and every switch: [docs/validation.md](docs/validation.md).
Cost per packet, stack and the switches that change them:
[docs/performance.md](docs/performance.md).

### Build systems

| | |
|---|---|
| CMake | `include(validate/extra/NanopbValidate.cmake)` after `find_package(Nanopb)`, then `nanopb_validate_generate(SRCS HDRS a.proto [OPTIONS --filter pkg.Msg])` and link `nanopb_validate`. |
| make | `include validate/extra/nanopb_validate.mk` (before nanopb's `extra/nanopb.mk`); `%.proto` builds `.pb.c/.h` and `_validate.c/.h`. |
| protoc | `--plugin=protoc-gen-nanopb-validate=validate/nanopb_validate/plugin/protoc-gen-nanopb-validate`, `--nanopb_out` before `--nanopb-validate_out`; see [docs/validation.md](docs/validation.md#with-protoc-directly). |

Both add-ons run `gen`, which the tests cover; the CMake and make files
themselves are not exercised by the tests.

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
  extra/               CMake and make add-ons
  examples/stress/     a full protocol: protos, captures, C round trip
  tests/py/            tool, dissector, CLI, security, performance, separation
  tests/c/             C tests of the runtime and generated code (SCons)
  docs/                validation, performance, Wireshark guide and reference, data generator
```

## Tests

    python -m nanopb_validate test --py          # ~2 minutes
    python -m nanopb_validate test --c           # SCons; on Windows without MSVC add TOOLS=mingw CC=... (zig/clang)
    python -m nanopb_validate test --security    # fuzz every filter: guard pages + UBSan
    python -m nanopb_validate test --perf        # budgets: filter <= 1.25 x decode, stack, context size

`tests/py/test_upstream_separation.py` fails if any nanopb file differs from
`UPSTREAM`.

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
