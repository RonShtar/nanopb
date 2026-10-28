# nanopb tools for Wireshark

Two Lua plugins for Wireshark, for Windows and Linux:

| File | What it does |
|------|--------------|
| `nanopb_studio.lua` | Adds a **Tools > nanopb** menu. From a directory of `.proto` files it generates merged nanopb C code with validation, and encoded sample data. It also installs the dissector below. |
| `nanopb_any_dissector.lua` | A protobuf dissector that decodes nested messages recursively and resolves `google.protobuf.Any` by its `type_url`, so one packet can carry many message types. |

The Lua side only collects input and shows results. The work happens in
`backend/nanopb_wireshark.py`, which uses this repository's generator,
validation plugin and data generator. Everything the menu does can also be run
from a terminal (see [Command line](#command-line)).

## Requirements

- Wireshark 3.6 or newer with Lua support. Check that **Help > About Wireshark > Wireshark** says "with Lua".
- Python 3.8+ with the generator dependencies:

      python -m pip install protobuf grpcio-tools

  On Windows, `python3` is often only the Microsoft Store stub; use `python` or the full path to `python.exe`.
- A checkout of this repository (the "nanopb project path").

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

`tests/fixtures/protos` is a working example.

## Installing

1. Find your personal Lua plugins folder: **Help > About Wireshark > Folders > Personal Lua Plugins**. It is usually:

   | OS | Folder |
   |----|--------|
   | Windows | `%APPDATA%\Wireshark\plugins` |
   | Linux | `~/.local/lib/wireshark/plugins` |

2. Install the studio plugin with the Python that has the generator dependencies. This records that Python and this checkout in `<plugins>/nanopb/studio_config.luadata`:

       python tools/wireshark/backend/nanopb_wireshark.py install-studio

   (add `--plugins-dir <folder>` if your folder differs).

3. Restart Wireshark, or use **Analyze > Reload Lua Plugins** (Ctrl+Shift+L).

There is no settings dialog. Each **Tools > nanopb** action asks for:

- **Input**: the protos directory with your unit subdirectories
- **Output directory**: where generated files go (empty = `<input>/../nanopb_out`)

Both fields start with the last values you used. The generate actions then
open a list of the units found in the input. Click a unit to select or
deselect it (all units start selected), or use **Select all** / **Select none**.
Then press **Generate**.

## Generating C code

**Tools > nanopb > Generate C (merged + validation)...**: input, output, then pick the units.

Each unit gets its own `<output>/<unit>/` folder:

- `<unit>.c` / `<unit>.h`: **all protos of the unit merged into one file, with
  validation**. They contain every `.pb.c/.pb.h` and `_validate.c/.h` (from the
  validate plugin, see `docs/validation.md`) of the unit and its dependencies,
  in dependency order, with the includes between them removed.
- The nanopb runtime as separate, unmodified files: `pb.h`, `pb_common.*`,
  `pb_encode.*`, `pb_decode.*`, `pb_validate.*` and `pb_filter_macros.h`.

The folder builds on its own. Drag it into
your firmware project, compile `<unit>.c` (plus the runtime `.c` files), and
add the folder to the include path, because the generated code uses
`#include <pb.h>`:

    gcc -I out/envelope -c out/envelope/*.c

## Generating raw data

**Tools > nanopb > Generate raw data...** (input, output, then pick the units) writes one encoded sample of every top-level message, from
`generator/nanopb_data_generator.py` (see `docs/DATA_GENERATOR.md`). The values
are random, but they respect your validation rules and nanopb limits
(`max_size`, `max_count`, ...).

**Tools > nanopb > Generate invalid raw data...** does the same with messages
that break a validation rule (`*_invalid.*`).

To choose messages, formats, counts, seeds or which field/rule to violate, use
`gen-data` on the [command line](#command-line).

Output goes to `<output>/<unit>/data/`, named after the C type (`demo_envelope_Envelope.*`):

- `.bin`: raw protobuf bytes
- `.h`: `static const uint8_t demo_envelope_Envelope_data[]` plus `DEMO_ENVELOPE_ENVELOPE_DATA_SIZE`
- `.hex`: a hex string. Wrap it into a capture with `text2pcap`; see [Testing the dissector](#testing-the-dissector).
- `.txt`: the field values that were encoded

## Dissector

**Tools > nanopb > Install or update dissector...** builds a schema from
**all** units of the protos directory. It copies `nanopb_any_dissector.lua` and
`nanopb/schema.luadata` next to `nanopb_studio.lua`, then reloads Lua plugins.
On versions without `reload_lua_plugins()`, press Ctrl+Shift+L yourself. Run it
again whenever your `.proto` files change.

The dialog asks for the input directory and a **port map**, for example `udp:5000=demo.envelope.Envelope,tcp:7000=demo.telemetry.Telemetry`.

The dissector picks the root message of a packet in this order:

1. The port map entry for the packet's UDP/TCP port. You can edit the map later under **Edit > Preferences > Protocols > NANOPB > Port map**.
2. The **Default message** preference. This is useful with **Analyze > Decode As... > UDP/TCP port > NANOPB** for ports that are not in the map.
3. `google.protobuf.Any`, if **Treat unknown payload as Any** is enabled (the default) and the payload is shaped like an `Any`.
4. A raw field-number / wire-type tree.

On ports that are **not** in the map, **Detect Any on any port (heuristic)**
(on by default) claims a UDP/TCP payload only when all of these hold:

- it is a well-formed `google.protobuf.Any`,
- its `type_url` names a message in the schema,
- its value is valid protobuf.

Other traffic is left alone.

Whenever it meets an `Any`, it reads `type_url`, looks up the part after the
last `/` (e.g. `demo.payloads.Command`) in the schema, and decodes `value` as
that message, recursively. This also works for an `Any` inside a message
inside another `Any`. Unknown types are shown as bytes with an expert warning.

Display filters:

- `nanopb.type_url == "type.googleapis.com/demo.payloads.Ping"`
- `nanopb.message == "demo.payloads.Command"`
- Any schema field as `nanopb.<full message name>.<field>`, e.g. `nanopb.demo.payloads.Ping.id > 5`.

Limitations:

- Each UDP datagram or TCP segment payload is decoded as one whole message. There is no TCP reassembly or length-prefix framing.
- Groups (proto2) are reported as unsupported.

## Live test in Wireshark

`tests/live/live_test.py` checks both plugins in your real Wireshark. Its test
packets (`tests/live/cases.py`) have exactly known contents:

- `Any` → `Command`,
- nested `Any` → `Envelope` → `Any` → `Ping`,
- a TCP Telemetry packet with every scalar kind,
- a bare `Any` on an unmapped port (heuristic),
- an unknown `Any` type,
- a malformed packet,
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
3. Go through [`tests/live/CHECKLIST.md`](tests/live/CHECKLIST.md). For every packet it lists the expected tree lines, expert info and a display filter, plus steps for the preferences, Decode As and every Tools > nanopb menu item.

If `tshark` is installed (Windows: `C:\Program Files\Wireshark\tshark.exe` is found automatically), the same checks run by themselves:

    python tools/wireshark/tests/live/live_test.py verify --pcap nanopb_live_test.pcap   # the pcap from step 2
    python tools/wireshark/tests/live/live_test.py live                                  # capture loopback + send + verify

Both print PASS/FAIL per packet. Add `--isolated` to load the dissector from
this repository with a fresh schema instead of the installed copy. This only
works when no copy is installed, since the two would clash.
`live_test.py checklist` regenerates `CHECKLIST.md` after you change the cases.

Tested with Wireshark/tshark 3.6.7 (Lua 5.2) on Windows: `verify` and `live`
pass 12/12.

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
   - every sample as a packet. Sample types without their own port go on the heuristic port, wrapped in an `Any`.
5. It dissects the capture with `tshark` and checks every packet.

With `--install`, the stress schema and port map go into your plugins folder,
and the studio's last input directory points at the stress protos. The ports are
`udp:5100=fleet.envelope.Envelope`, `tcp:5101=fleet.telemetry.Frame` and
`udp:5102=fleet.status.Status`, the heuristic `Any` port is `udp/5199`, and
Decode As uses `udp/5103` → `fleet.cmd.Command`. Then reload Lua plugins and
open `stress.pcap`. `live_test.py setup --reset-config` switches back to the
small test schema.

## Command line

Every menu action maps to a backend subcommand. All of them accept
`--protos-root`, `-I <extra include>`, and `--nanopb-root` (default: this
checkout).

    python tools/wireshark/backend/nanopb_wireshark.py units             --protos-root P [--names-only]
    python tools/wireshark/backend/nanopb_wireshark.py gen-c             --protos-root P --out O [--unit U] [--no-runtime] [--no-validate]
    python tools/wireshark/backend/nanopb_wireshark.py gen-data          --protos-root P --out O [--unit U] [--messages A,B] [--formats bin,c,hex] [--count N] [--seed S] [--invalid [--field F] [--rule R]]
    python tools/wireshark/backend/nanopb_wireshark.py schema            --protos-root P --out schema.luadata
    python tools/wireshark/backend/nanopb_wireshark.py install-dissector --protos-root P [--plugins-dir D] [--port-map MAP]
    python tools/wireshark/backend/nanopb_wireshark.py install-studio    [--plugins-dir D]

Output is JSON followed by a final `__EXIT__=<status>` line, which the Lua side uses to detect errors.

## Troubleshooting

- **"Backend did not run"**: the `python` path in `<plugins>/nanopb/studio_config.luadata` is wrong, or points to the Windows Store stub. Run `install-studio` again with the right Python.
- **`protoc failed`**: run the same subcommand in a terminal to see the full protoc error. Also check that `grpcio-tools` and `protobuf` are installed for *that* Python.
- **Menu or dissector missing**: check **Help > About Wireshark > Plugins** for load errors, and make sure the files are in the *Personal Lua Plugins* folder.
- **`pb_callback_t` in the generated header**: a string, bytes or repeated field has no `max_size` / `max_count` in its `.options` file.

## Tests

    python -m unittest discover -s tools/wireshark/tests -v

- `test_backend.py` needs only the generator dependencies.
- `test_dissector.py` runs both Lua plugins and the live test cases against a mock Wireshark API (`tests/wireshark_mock.lua`). It needs `pip install lupa` and is skipped without it.
- `test_tshark.py` dissects the live test capture with a real `tshark`. It is skipped when `tshark` isn't found, or when a copy of the dissector is installed in the personal plugins folder.
