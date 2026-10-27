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
- Extra include directories can be set in Settings.
- Imported files from outside the unit, such as `google/protobuf/any.proto`, are generated and merged into the unit too. Each unit is self-contained.
- If no `google/protobuf/any.options` is found on the include path, `Any` gets static storage of `type_url` 128 / `value` 256 bytes (`backend/include/google/protobuf/any.options`). Your own file takes precedence.

`tests/fixtures/protos` is a working example.

## Installing

1. Find your personal Lua plugins folder: **Help > About Wireshark > Folders > Personal Lua Plugins**. It is usually:

   | OS | Folder |
   |----|--------|
   | Windows | `%APPDATA%\Wireshark\plugins` |
   | Linux | `~/.local/lib/wireshark/plugins` |

2. Install the studio plugin. Either let the backend copy it and pre-fill the Python and project paths:

       python tools/wireshark/backend/nanopb_wireshark.py install-studio

   (add `--plugins-dir <folder>` if your folder differs), or copy `tools/wireshark/nanopb_studio.lua` into that folder yourself. On Linux a symlink also works.

3. Restart Wireshark, or use **Analyze > Reload Lua Plugins** (Ctrl+Shift+L).

4. Open **Tools > nanopb > Settings...** and set:
   - **nanopb project path**: this repository's root (the folder containing `generator/`)
   - **Protos directory**: the directory with your unit subdirectories
   - **Output directory**: where generated files go (empty = `<protos>/../nanopb_out`)
   - **Extra proto include dirs**: `;`-separated, optional
   - **Python executable**: e.g. `python`, `python3` or a full path

   Saving runs **List proto units**, so you see straight away whether everything resolves. Settings are stored in `<plugins>/nanopb/studio_config.luadata`.

## Generating C code

**Tools > nanopb > Generate C (merged + validation)...**

- **Units**: comma-separated, or empty for all.
- **Copy nanopb runtime sources (y/n)**: also copies `pb.h`, `pb_common.*`, `pb_encode.*`, `pb_decode.*` and, with validation, `pb_validate.*`, so the output folder builds on its own.
- **Validation code (y/n)**: includes the code produced by the validate plugin (see `docs/validation.md`).

The result is `<output>/<unit>/<unit>.c` and `<unit>.h`. They contain every
`.pb.c/.pb.h` and `_validate.c/.h` of the unit and its dependencies, in
dependency order, with the includes between them removed. Drag the folder into
your firmware project, compile `<unit>.c` (plus the runtime `.c` files), and
add the folder to the include path, because the generated code uses
`#include <pb.h>`:

    gcc -I out/envelope -c out/envelope/*.c

## Generating raw data

**Tools > nanopb > Generate raw data...** writes encoded sample messages from
`generator/nanopb_data_generator.py` (see `docs/DATA_GENERATOR.md`). The values
are random, but they respect your validation rules and nanopb limits
(`max_size`, `max_count`, ...).

- **Messages**: short (`Envelope`) or full (`demo.envelope.Envelope`) names; empty = all top-level messages.
- **Formats**: any of `bin`, `c`, `hex`.
- **Samples per message** and **Seed**: give reproducible series (sample *i* uses seed + *i*).
- **Invalid data**: generates messages that break a validation rule. You can choose which fields and rules to violate.

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

The dialog asks for a **port map**, for example `udp:5000=demo.envelope.Envelope,tcp:7000=demo.telemetry.Telemetry`.

The dissector picks the root message of a packet in this order:

1. The port map entry for the packet's UDP/TCP port. You can edit the map later under **Edit > Preferences > Protocols > NANOPB > Port map**.
2. The **Default message** preference. This is useful with **Analyze > Decode As... > UDP/TCP port > NANOPB** for ports that are not in the map.
3. `google.protobuf.Any`, if **Treat unknown payload as Any** is enabled (the default) and the payload is shaped like an `Any`.
4. A raw field-number / wire-type tree.

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

### Testing the dissector

    python tools/wireshark/backend/nanopb_wireshark.py gen-data --protos-root tools/wireshark/tests/fixtures/protos --unit envelope --messages Envelope --formats hex --out out
    # text2pcap wants an offset + hex dump:
    python -c "import sys; d=open(sys.argv[1]).read().strip(); print('000000 ' + ' '.join(d[i:i+2] for i in range(0, len(d), 2)))" out/envelope/data/demo_envelope_Envelope.hex > dump.txt
    text2pcap -u 40000,5000 dump.txt envelope.pcap
    tshark -r envelope.pcap -V -O nanopb

## Command line

Every menu action maps to a backend subcommand. All of them accept
`--protos-root`, `-I <extra include>`, and `--nanopb-root` (default: this
checkout).

    python tools/wireshark/backend/nanopb_wireshark.py units             --protos-root P
    python tools/wireshark/backend/nanopb_wireshark.py gen-c             --protos-root P --out O [--unit U] [--with-runtime] [--no-validate]
    python tools/wireshark/backend/nanopb_wireshark.py gen-data          --protos-root P --out O [--unit U] [--messages A,B] [--formats bin,c,hex] [--count N] [--seed S] [--invalid [--field F] [--rule R]]
    python tools/wireshark/backend/nanopb_wireshark.py schema            --protos-root P --out schema.luadata
    python tools/wireshark/backend/nanopb_wireshark.py install-dissector --protos-root P [--plugins-dir D] [--port-map MAP]
    python tools/wireshark/backend/nanopb_wireshark.py install-studio    [--plugins-dir D]

Output is JSON followed by a final `__EXIT__=<status>` line, which the Lua side uses to detect errors.

## Troubleshooting

- **"Backend did not run"**: the Python path in Settings is wrong, or points to the Windows Store stub.
- **`protoc failed`**: run the same subcommand in a terminal to see the full protoc error. Also check that `grpcio-tools` and `protobuf` are installed for *that* Python.
- **Menu or dissector missing**: check **Help > About Wireshark > Plugins** for load errors, and make sure the files are in the *Personal Lua Plugins* folder.
- **`pb_callback_t` in the generated header**: a string, bytes or repeated field has no `max_size` / `max_count` in its `.options` file.

## Tests

    python -m unittest discover -s tools/wireshark/tests -v

`test_backend.py` needs only the generator dependencies. `test_dissector.py`
runs both Lua plugins against a mock Wireshark API (`tests/wireshark_mock.lua`)
using `pip install lupa`. It is skipped if `lupa` is missing. It doesn't replace
a check in a real Wireshark.
