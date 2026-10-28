# nanopb tools for Wireshark

Two Lua plugins for Wireshark, for Windows and Linux:

| File | What it does |
|------|--------------|
| `nanopb_studio.lua` | Adds a **Tools > nanopb** menu. From a directory of `.proto` files it generates merged nanopb C code with validation and packet filters, and one capture of test packets that pass or are dropped by validation. |
| `nanopb_any_dissector.lua` | A protobuf dissector that decodes nested messages recursively, resolves `google.protobuf.Any` by its `type_url`, and checks every packet against your `validate.proto` rules: **Validation: PASSED** or **DROPPED**, exactly as the generated nanopb filter would decide. |

The Lua side only collects input and shows results. The work happens in
`backend/nanopb_wireshark.py`, which uses this repository's generator,
validation plugin and data generator. Everything the menu does can also be run
from a terminal (see [Command line](#command-line)).

## Requirements

- Wireshark 3.6 or newer with Lua support. Check that **Help > About Wireshark > Wireshark** says "with Lua".
- Python 3.8+ with the generator dependencies:

      python -m pip install protobuf grpcio-tools

  On Windows, `python3` is often only the Microsoft Store stub; use `python` or the full path to `python.exe`.

## Protos directory layout

Each subdirectory of the protos directory that contains `.proto` files is a
**unit**. A unit is generated as one C source and one header. Put each
`.options` file next to its `.proto`, as usual for nanopb.

```
my_protos/
  telemetry/            -> telemetry.c + telemetry.h
    common.proto
    common.options
    telemetry.proto
    telemetry.options
  envelope/             -> envelope.c + envelope.h
    envelope.proto      (import "payloads.proto"; import "google/protobuf/any.proto";)
    payloads.proto
```

- Imports may be relative to the unit (`import "payloads.proto";`) or to the protos directory (`import "envelope/payloads.proto";`).
- Extra include directories can be added as `extra_includes = "dir1;dir2"` in `<plugins>/nanopb/studio_config.luadata`.
- Imported files from outside the unit, such as `google/protobuf/any.proto`, are generated and merged into the unit too. Each unit is self-contained.
- If no `google/protobuf/any.options` is found on the include path, `Any` gets static storage of `type_url` 128 / `value` 256 bytes (`backend/include/google/protobuf/any.options`). Your own file takes precedence.

`tests/fixtures/protos` is a working example; `tests/fixtures/rules` uses every validation rule.

## Installing

One command, run with the Python that has the requirements:

    python tools/wireshark/backend/nanopb_wireshark.py install-studio

It installs into your personal Lua plugins folder (**Help > About Wireshark >
Folders > Personal Lua Plugins**; `%APPDATA%\Wireshark\plugins` on Windows,
`~/.local/lib/wireshark/plugins` on Linux, or `--plugins-dir <folder>`):

- `nanopb_studio.lua` and `nanopb_any_dissector.lua`;
- `nanopb/project/`: a copy of the generator, the nanopb runtime (`pb*.c/.h`, `pb_validate.*`) and the backend. The plugin uses this copy, so it never needs to know where this repository is. The Lua sources inside it are named `.lua.src`, because Wireshark loads every `.lua` file below the plugins folder;
- `nanopb/studio_config.luadata`: the Python to use and your last directories and port map.

Then restart Wireshark or press Ctrl+Shift+L (**Analyze > Reload Lua Plugins**).
Run `install-studio` again after updating this repository. With `--dev` the
plugin runs this checkout directly instead of a copy.

## Using it

**Tools > nanopb** has four items. Each asks only for

- **Input**: the protos directory with your unit subdirectories, and
- **Output directory** (empty = `<input>/../nanopb_out`),

both prefilled with what you used last. The generate actions then show the
units found in the input: click a unit to select or deselect it (all start
selected), or use **Select all** / **Select none**, then press **Generate**.

| Menu | Result |
|------|--------|
| Generate C (merged + validation) | `<output>/<unit>/<unit>.c/.h` plus the nanopb runtime |
| Generate test packets (passed + dropped) | `<output>/nanopb_test_packets.pcapng`, opened in Wireshark |
| Install or update dissector | the dissector and schema, for real traffic |
| About | paths, Python, port map |

### Generating C code

Each unit gets its own `<output>/<unit>/` folder:

- `<unit>.c` / `<unit>.h`: **all protos of the unit merged into one file, with
  validation**. They contain every `.pb.c/.pb.h` and `_validate.c/.h` (from the
  validate plugin, see `docs/validation.md`) of the unit and its dependencies,
  in dependency order, with the includes between them removed.
- The nanopb runtime as separate, unmodified files: `pb.h`, `pb_common.*`,
  `pb_encode.*`, `pb_decode.*`, `pb_validate.*` and `pb_filter_macros.h`.

The merged header exports, for every message,

```c
bool pb_validate_<msg>(const <msg> *msg, pb_violations_t *violations);
```

and, for each **protocol entrypoint**, a packet filter that decodes,
validates and returns `0` (accept) or `-1` (drop):

```c
int <Msg>_filter_udp(void *ctx, const uint8_t *packet, size_t packet_size);
int <Msg>_filter_tcp(void *ctx, const uint8_t *packet, size_t packet_size, bool is_to_server);
```

The entrypoints are the messages of the port map (the one the dissector uses);
without one, the unit's root messages (those no other message of the unit uses
as a field or Any payload). An entrypoint whose dispatch would be ambiguous
(e.g. two `Any` fields) gets a `single`-mode filter: decode and validate the
entrypoint itself. The result window lists the exported filters.

The folder builds on its own. Drag it into your firmware project, compile
`<unit>.c` plus the runtime `.c` files, and add the folder to the include path,
because the generated code uses `#include <pb.h>`:

    gcc -I out/envelope -c out/envelope/*.c

### Generating test packets

One button makes a capture with, for every message of the selected units,

- valid samples (expected **PASSED**), and
- one sample per validation rule, breaking exactly that rule (expected **DROPPED**),

from `generator/nanopb_data_generator.py`. Sample values respect nanopb's
limits (`max_size`, `max_count`, ...), so a dropped packet is dropped by the
validator, not by a decode error. Rules that cannot be broken with decodable
data, or that the C validator does not enforce, are listed as not generated.

Root messages are sent raw on their port (your port map, or one UDP port per
unit root from 15000, which is then saved as your port map). Every other
message is wrapped in a `google.protobuf.Any` and sent on `udp/15999`.

The backend refreshes the dissector and schema in your plugins folder, the
capture opens, and Lua plugins reload when the schema changed. The result
window has **Show dropped only** (filter `nanopb.validation == "dropped"`),
**Show all** and **Open output folder**. Next to the capture:

- `nanopb_test_packets.json`: per frame the message, port, expected verdict, violated field and rule, seed and bytes;
- `nanopb_test_packets.txt`: the same as a table, plus what was not generated.

Each packet also carries its expectation as a packet comment
(`expect=DROPPED msg=... field=... rule=...`, column `frame.comment`).

### Dissector

**Install or update dissector** builds a schema from **all** units of the
protos directory, with their validation rules, and asks for a **port map**, for
example `udp:5000=demo.envelope.Envelope,tcp:7000=demo.telemetry.Telemetry`.
Run it again whenever your `.proto` files change (Generate test packets does
this for you).

The dissector picks the root message of a packet in this order:

1. The port map entry for the packet's UDP/TCP port. You can edit the map later under **Edit > Preferences > Protocols > NANOPB > Port map**.
2. The **Default message** preference. This is useful with **Analyze > Decode As... > UDP/TCP port > NANOPB** for ports that are not in the map.
3. `google.protobuf.Any`, if **Treat unknown payload as Any** is enabled (the default) and the payload is shaped like an `Any`.
4. A raw field-number / wire-type tree.

On ports that are **not** in the map, **Detect Any on any port (heuristic)**
(on by default) claims a UDP/TCP payload only when it is a well-formed
`google.protobuf.Any` whose `type_url` names a message in the schema and whose
value is valid protobuf. Other traffic is left alone.

Whenever it meets an `Any`, it reads `type_url`, looks up the part after the
last `/` (e.g. `demo.payloads.Command`) in the schema, and decodes `value` as
that message, recursively. Unknown types are shown as bytes with an expert warning.

## Validation in Wireshark

Every packet decoded as a schema message gets a **Validation** subtree:

```
Validation: DROPPED (1 problem)
    numbers.i64: int64.gte - must be >= -5000000000 (got -5000000001)
        Field: numbers.i64
        Detail: must be >= -5000000000 (got -5000000001)
        [Expert Info (Warning/Protocol): ...]
```

The Info column ends in `[PASSED]` or `[DROPPED <rule> <field>]`.

| Display filter | Meaning |
|----------------|---------|
| `nanopb.validation == "dropped"` | packets the nanopb filter would reject |
| `nanopb.validation == "passed"` | packets it would accept |
| `nanopb.validation.rule == "string.min_len"` | a specific rule failed |
| `nanopb.validation.field contains "readings"` | a problem in that field |
| `nanopb.validation.violation` | expert info: a rule was violated |
| `nanopb.validation.decode` | expert info: `pb_decode` would fail |
| `nanopb.validation.unchecked` | a rule that is listed but not checked |

The verdict follows `pb_validate.c` and the code nanopb-validate generates:

- proto3 fields without presence are checked at their default value when absent (as in the C struct); `optional` fields and sub-messages only when present; a `oneof` arm only when selected;
- `required` is checked on fields with presence (the C struct has a `has_` flag);
- strings are compared up to the first NUL, lengths in bytes; bytes compare all bytes;
- `float` rule constants are compared as `float`, 64-bit values exactly;
- email, hostname, IPv4 and IPv6 use the same checks as `pb_validate.c`;
- sub-messages and `repeated` items are checked recursively, with paths such as `lists.inners[1].code`;
- a packet is also DROPPED when `pb_decode` would fail: malformed data, a string or array larger than its `max_size` / `max_count`, a wrong wire type, an out-of-range `int32`, a missing proto2 `required` field.

Differences from C, on purpose:

- all problems are listed (C stops at the first one);
- `Timestamp` rules (`gt_now`, `lt_now`, `within`) use the packet's capture time instead of the clock;
- with **Validate Any payloads** (on by default) the message inside an `Any` is validated too, as the filter of an `Any` entrypoint does; plain `pb_validate_<msg>()` does not look into `Any`.

Not checked, and never a reason to drop (nanopb-validate refuses to generate C
code for them): `string.pattern`, `min_bytes` / `max_bytes`,
`oneof_required`, `map.no_sparse`, and the message rules `requires`, `mutex`,
`at_least`. Rules of callback fields (no `max_size` / `max_count`) are listed
as not checked, since `pb_validate` skips them.

Preferences (**Edit > Preferences > Protocols > NANOPB**): **Check validation
rules** (on) and **Validate Any payloads** (on).

Limitations of the dissector:

- Each UDP datagram or TCP segment payload is decoded as one whole message. There is no TCP reassembly or length-prefix framing.
- Groups (proto2) are reported as unsupported.

## Live test in Wireshark

`tests/live/live_test.py` checks both plugins in your real Wireshark. Its test
packets (`tests/live/cases.py`) have exactly known contents and verdicts:

- `Any` → `Command`,
- nested `Any` → `Envelope` → `Any` → `Ping` (DROPPED: `body` only allows Ping and Command),
- a TCP Telemetry packet with every scalar kind,
- a bare `Any` on an unmapped port (heuristic),
- an unknown `Any` type (DROPPED),
- a malformed packet (DROPPED),
- a Decode As case,
- 5 generated Envelopes.

1. Install the plugins and point the studio at the test protos:

       python tools/wireshark/tests/live/live_test.py setup

   This writes to your personal plugins folder. Add `--reset-config` if the
   studio is already configured for your own protos. Then reload Lua plugins
   in Wireshark (Ctrl+Shift+L).
2. Get the packets into Wireshark, either way:
   - `live_test.py pcap` writes `nanopb_live_test.pcap`; open it. Packet *N* is case *N*.
   - Or capture on loopback, which on Windows is the Npcap *Adapter for loopback traffic capture* and on Linux is `lo`, while running `live_test.py send` (`--repeat N`, `--interval S`).
3. Go through [`tests/live/CHECKLIST.md`](tests/live/CHECKLIST.md). For every packet it lists the expected tree lines, verdict, expert info and a display filter, plus steps for the preferences, Decode As and every Tools > nanopb menu item.

If `tshark` is installed (Windows: `C:\Program Files\Wireshark\tshark.exe` is found automatically), the same checks run by themselves:

    python tools/wireshark/tests/live/live_test.py verify --pcap nanopb_live_test.pcap   # the pcap from step 2
    python tools/wireshark/tests/live/live_test.py live                                  # capture loopback + send + verify

Both print PASS/FAIL per packet. Add `--isolated` to load the dissector from
this repository with a fresh schema instead of the installed copy. This only
works when no copy is installed, since the two would clash.
`live_test.py checklist` regenerates `CHECKLIST.md` after you change the cases.

## Stress example: many protos, one output

`examples/stress/protos` has one unit, `fleet`, made of 6 protos. It also imports
`shared/units.proto` from another folder, plus `google/protobuf/any.proto` and
`timestamp.proto`. Together they use:

- proto2 and proto3 in one unit, with proto2 `required`/defaults;
- nested messages and nested enums;
- a 5-way `oneof`;
- a `map`;
- packed and unpacked repeated fields, and every scalar type;
- a `Timestamp`;
- several `Any` fields, including a `Batch` of `Any` that can hold Envelopes or Batches again;
- a project-specific `google/protobuf/any.options`;
- validation rules on most fields.

One command runs everything:

    python tools/wireshark/examples/stress/stress_test.py            # add --install to load it into your Wireshark

It goes through these steps:

1. `gen-c` merges all 36 generated files into `nanopb_stress_out/fleet/fleet.c` and `fleet.h`, and adds the nanopb runtime.
2. `gen-data` writes samples for all 16 messages (`--count N` per message).
3. It compiles `fleet.c` and the runtime with `-std=c11 -pedantic -Wall -Wextra -Werror -Wconversion -Wcast-qual`. Then a generated C program decodes, validates and re-encodes every sample. nanopb always encodes repeated scalars packed, so samples with unpacked fields are compared by decoded content, not bytes. The compiler comes from `CC`, `gcc`/`clang`, or `pip install ziglang`.
4. It writes `nanopb_stress_out/stress.pcap`, and lists each packet with its expected tree in `stress_packets.txt`. The capture has:
   - 10 hand-made packets: a Frame with 3 `Any` readings, a map and a Timestamp; a `oneof` command; a proto2 status; `Any` recursion 4 levels deep; heuristic; Decode As; malformed;
   - every sample as a packet. Sample types without their own port go on the heuristic port, wrapped in an `Any` (samples larger than the project's 512-byte `Any.value` are expected to be DROPPED).
5. It dissects the capture with `tshark` and checks every packet, including its verdict.

With `--install`, the stress schema and port map go into your plugins folder,
and the studio's last input directory points at the stress protos. The ports are
`udp:5100=fleet.envelope.Envelope`, `tcp:5101=fleet.telemetry.Frame` and
`udp:5102=fleet.status.Status`, the heuristic `Any` port is `udp/5199`, and
Decode As uses `udp/5103` → `fleet.cmd.Command`. Then reload Lua plugins and
open `stress.pcap`. `live_test.py setup --reset-config` switches back to the
small test schema.

## Command line

Every menu action maps to a backend subcommand. All of them accept
`--protos-root`, `-I <extra include>`, and `--nanopb-root` (default: the
checkout or installed copy containing the script).

    python tools/wireshark/backend/nanopb_wireshark.py gen-c             --protos-root P --out O [--unit U] [--port-map MAP] [--no-filter] [--no-runtime] [--no-validate]
    python tools/wireshark/backend/nanopb_wireshark.py gen-packets       --protos-root P --out O [--unit U] [--port-map MAP] [--any-port 15999] [--valid 2] [--max-invalid 40] [--seed 1] [--format pcapng|pcap] [--plugins-dir D | --no-install]
    python tools/wireshark/backend/nanopb_wireshark.py install-dissector --protos-root P [--plugins-dir D] [--port-map MAP]
    python tools/wireshark/backend/nanopb_wireshark.py install-studio    [--plugins-dir D] [--dev]
    python tools/wireshark/backend/nanopb_wireshark.py gen-data          --protos-root P --out O [--unit U] [--messages A,B] [--formats bin,c,hex] [--count N] [--seed S] [--invalid [--field F] [--rule R]]
    python tools/wireshark/backend/nanopb_wireshark.py units             --protos-root P [--names-only]
    python tools/wireshark/backend/nanopb_wireshark.py schema            --protos-root P --out schema.luadata

`gen-data` writes single encoded samples (`.bin`, a C array `.h`, `.hex`,
and the values as `.txt`) to `<out>/<unit>/data/`; see `docs/DATA_GENERATOR.md`.

Output is JSON followed by a final `__EXIT__=<status>` line, which the Lua side uses to detect errors.

## Troubleshooting

- **"Backend did not run"**: the `python` path in `<plugins>/nanopb/studio_config.luadata` is wrong, or points to the Windows Store stub. Run `install-studio` again with the right Python.
- **"nanopb backend not found"**: run `install-studio`.
- **`protoc failed`**: run the same subcommand in a terminal to see the full protoc error. Also check that `grpcio-tools` and `protobuf` are installed for *that* Python.
- **Menu or dissector missing**: check **Help > About Wireshark > Plugins** for load errors, and make sure the files are in the *Personal Lua Plugins* folder.
- **A packet shows no Validation subtree**: it was not decoded as a schema message (raw tree, or claimed by another protocol). Add its port to the port map.
- **`pb_callback_t` in the generated header**: a string, bytes or repeated field has no `max_size` / `max_count` in its `.options` file.

## Tests

    python -m unittest discover -s tools/wireshark/tests -v

- `test_backend.py` needs only the generator dependencies. With a C compiler (`CC`, `gcc`/`clang`, or `pip install ziglang`) it also checks that every `gen-packets` verdict is what `pb_decode` + `pb_validate` decide in C.
- `test_dissector.py` runs both Lua plugins, the live test cases, the validation rules and generated captures against a mock Wireshark API (`tests/wireshark_mock.lua`). It needs `pip install lupa` and is skipped without it.
- `test_tshark.py` dissects the live test capture and generated captures with a real `tshark` (Lua 5.2), including the `nanopb.validation == "dropped"` filter. It is skipped when `tshark` isn't found, or when a copy of the dissector is installed in the personal plugins folder.
