# Nanopb: Wireshark tools user guide

This guide covers installing the nanopb tools for Wireshark and using them from
start to finish. For every option and file format, see the reference,
[tools/wireshark/README.md](../tools/wireshark/README.md).

## What the tools do

The tools are two Lua plugins for Wireshark, plus a Python backend that uses
this repository's generator.

- **The nanopb dissector** decodes your protobuf packets in Wireshark:
  - nested messages and `google.protobuf.Any`, resolved by `type_url`;
  - a **Validation: PASSED / DROPPED** verdict on every packet, using your
    `validate.proto` rules, exactly as the generated C filter would decide.
- **The Tools > nanopb menu** has three jobs:
  - it generates merged nanopb C code with validators and packet filters, ready
    to drop into firmware;
  - it creates a capture of test packets that should pass or be dropped;
  - it loads all your protocols into Wireshark.

The tools build on nanopb and its validation extension. They don't change
them. See [Updating nanopb](#updating-nanopb).

### Protocols: one folder each

Point the tools at a **protos directory**. Every subdirectory that contains
`.proto` files is one **protocol** (a "unit"):

```
my_protos/
  fleet/                 protocol "fleet"   -> FLEET in Wireshark
    envelope.proto       import "google/protobuf/any.proto"; import "shared/units.proto";
    envelope.options
    sensors.proto
    sensors.options
  shared/                protocol "shared"  -> SHARED in Wireshark
    units.proto
```

- Imports may be relative to the folder (`import "sensors.proto";`) or to the
  protos directory (`import "shared/units.proto";`).
- Put each `.options` file next to its `.proto`, as usual for nanopb. Give
  strings, bytes and repeated fields a `max_size` / `max_count`. Otherwise the
  generated code uses callbacks.
- A folder that imports another folder already contains that folder's
  messages. In the example, `fleet.pb.c` includes `shared`'s types. That's why
  Generate C starts with `shared` deselected and marks it "already merged into
  fleet": linking both would define the same symbols twice.

### Packets: an Any whose type_url is the opcode

A protocol's packet is a `google.protobuf.Any`. Its `type_url` (for example
`type.googleapis.com/fleet.envelope.Envelope`) names the message inside, so
it works as the opcode. Any `Any` fields inside the message are resolved the
same way, at most 4 levels deep. Oneofs are ordinary fields.

## Installation

### 1. Check the requirements

- **Wireshark 3.6 or newer, with Lua.** Help > About Wireshark > Wireshark
  must say "with Lua". The tools are tested with 3.6.7.
- **Python 3.8 or newer**, with the generator dependencies:

      python -m pip install protobuf grpcio-tools

  On Windows, `python3` is often only the Microsoft Store stub. Use `python`,
  or the full path to `python.exe`, and run `python --version` to be sure.

### 2. Install the plugins

From a checkout of this repository, using the Python from step 1, run:

    python tools/wireshark/backend/nanopb_wireshark.py install-studio

This copies into your *Personal Lua Plugins* folder (shown under Help >
About Wireshark > Folders): `%APPDATA%\Wireshark\plugins` on Windows,
`~/.local/lib/wireshark/plugins` on Linux.

| Installed | Purpose |
|-----------|---------|
| `nanopb_studio.lua` | the Tools > nanopb menu |
| `nanopb_any_dissector.lua` | the dissector |
| `nanopb/project/` | a private copy of the generator, the runtime and the backend, so the plugins never depend on where this checkout is |
| `nanopb/studio_config.luadata` | the Python to use, and your last directories and port map |

The copy records the Python that ran `install-studio`. To use a different
folder, add `--plugins-dir <folder>`. For tool development, `--dev` runs this
checkout directly instead of a copy.

### 3. Start Wireshark

Restart Wireshark, or press **Ctrl+Shift+L** (Analyze > Reload Lua Plugins).
To check that it worked:

- **Tools > nanopb** shows four items: Generate C, Generate test packets,
  Load protos directory into Wireshark, and About;
- **Tools > nanopb > About** shows the plugins folder, the Python and the
  project copy;
- Help > About Wireshark > Plugins lists both `.lua` files with no error.

### Updating and uninstalling

- **To update the tools:** pull this repository and run `install-studio`
  again. Your settings in `studio_config.luadata` are kept.
- **To uninstall:** close Wireshark and delete `nanopb_studio.lua`,
  `nanopb_any_dissector.lua` and the `nanopb/` folder from the plugins folder.

## First run, step by step

The repository ships an example protos directory,
`tools/wireshark/examples/stress/protos` (`fleet` and `shared`). Use it to try
every step before switching to your own protos.

### Step 1: load your protocols into Wireshark

1. **Tools > nanopb > Load protos directory into Wireshark**.
2. Enter the protos directory. That's the only question.
3. The result window lists the protocols it loaded, for example `FLEET` and
   `SHARED`, and Lua plugins reload by themselves.

Run this again whenever you add a folder or change a `.proto` file. Your port
map and protocol ports are kept.

### Step 2: choose which protocol decodes your traffic

There are two ways, and you can use both:

- **One protocol for everything:** Edit > Preferences > Protocols > NANOPB >
  **Protocol** = `fleet`. You can also right-click a NANOPB packet and choose
  Protocol Preferences > Protocol. Every NANOPB packet that has no port map
  entry is then decoded as a fleet packet.
- **Per port:** right-click a packet, choose **Decode As...**, set the field to
  *UDP port* (or *TCP port*) and the value to your port, and pick **FLEET** in
  the *Current* column. On the command line, the same is
  `tshark -d udp.port==16000,fleet`.

A decoded packet shows:

- in the Protocol column, `FLEET`;
- in the Info column, the message the `type_url` selected and the verdict,
  e.g. `nanopb fleet fleet.envelope.Envelope (120 bytes) [PASSED]`;
- in the tree, the decoded fields and a **Validation** subtree listing every
  rule that failed, with its field path.

When a packet is decoded as a protocol:
- a `type_url` naming a message of another protocol gives `filter.unknown_type`;
- `Any` nested more than 4 levels deep gives `filter.depth`.

The C filter makes the same decisions.

If the folder name is already a Wireshark protocol, for example `ip`, the
entry is called `NANOPB_IP` instead.

### Step 3: generate test packets

1. **Tools > nanopb > Generate test packets (passed + dropped)**.
2. Enter the input directory and an output directory (empty means
   `<input>/../nanopb_out`), select the protocols in the list, and press
   **Generate**.
3. You get, for every message of every selected protocol:
   - valid samples, which are expected to be **PASSED**;
   - one sample per validation rule, breaking only that rule, which are
     expected to be **DROPPED**.
4. The capture opens by itself. Each protocol has its own UDP port: the first
   on 16000, the next on 16001, and so on. Those ports are already mapped to
   their protocol, so no Decode As is needed.
5. In the result window:
   - **Show dropped only** applies the filter `nanopb.validation == "dropped"`;
   - **Show all** removes it again;
   - **Open output folder** opens the output directory.

The output directory contains:

| File | Contents |
|------|----------|
| `nanopb_test_packets.pcapng` | the capture; each packet's comment says `expect=PASSED/DROPPED msg=... field=... rule=...` |
| `nanopb_test_packets.json` | the manifest: per frame, the message, port, expected verdict, broken rule and bytes |
| `nanopb_test_packets.txt` | the same as a table, plus the rules that couldn't be generated |
| `<protocol>/packets/packet_NNN_<Message>_<passed\|dropped>.h` | each packet as a C array, `static const uint8_t ..._data[]` plus `..._DATA_SIZE` |
| `<protocol>/packets/packet_NNN_<Message>_<passed\|dropped>.hex` | the same bytes as a hex stream |

The `.h` files are meant for firmware unit tests: feed each array to the
generated filter and expect `0` (passed) or `-1` (dropped).

### Step 4: generate the C code

1. **Tools > nanopb > Generate C (merged + validation)**.
2. Enter the input and output directories, select the protocols, and press
   **Generate**. Units that are already merged into another one start
   deselected.
3. Each protocol gets exactly four files in `<output>/<protocol>/`:

| File | Contents |
|------|----------|
| `<protocol>.pb.h` / `.pb.c` | every message struct, descriptor and `PB_BIND` of the protocol's protos and their imports, plus the packet filters |
| `<protocol>_validate.h` / `.c` | a `pb_validate_<Message>()` for every message |

The result window lists the exported filters and the smallest validation
buffer settings for this protocol.

## Using the generated C code

Add the four files to a project that already has the nanopb runtime on its
include path: `pb.h`, `pb_common.*`, `pb_encode.*`, `pb_decode.*`,
`pb_validate.*` and `pb_filter_macros.h`, all from this repository. For
example:

    gcc -I out/fleet -I path/to/nanopb -c out/fleet/fleet.pb.c out/fleet/fleet_validate.c

**One filter for the whole protocol** (for protocols that import
`google/protobuf/any.proto`):

```c
#include "fleet.pb.h"

/* 0 = accept, -1 = drop */
int fleet_filter_udp(void *ctx, const uint8_t *packet, size_t packet_size);
int fleet_filter_tcp(void *ctx, const uint8_t *packet, size_t packet_size, bool is_to_server);
```

The filter decodes the packet as an `Any` and switches on its `type_url` to
the message. It then decodes and validates that message, and checks nested
`Any` fields the same way. Each message also has its own filter
(`fleet_envelope_Envelope_filter_udp`, ...) for packets that are that message
itself, and you can call a validator directly:

```c
#include "fleet_validate.h"

bool ok = pb_validate_fleet_envelope_Envelope(&msg, NULL);  /* NULL: pass/fail only */
```

Build switches such as `PB_VALIDATE_MAX_PATH_DEPTH` or
`PB_VALIDATE_FILTER_MAX_ANY_DEPTH` must be the same for every file of the
build. For what each one costs, see [Validation performance](validation_performance.md);
for the rules, see [Validation](validation.md).

## Everyday tasks

| I want to... | Do this |
|--------------|---------|
| add a protocol | add a folder with its `.proto` files, then **Load protos directory into Wireshark** |
| change a message | edit the `.proto`, then **Load protos directory** (dissector) and **Generate C** (firmware) |
| decode a port as a protocol | Decode As > UDP/TCP port > `<PROTOCOL>` |
| decode a port as one specific message | Edit > Preferences > Protocols > NANOPB > Port map, e.g. `udp:5000=fleet.envelope.Envelope` |
| see only invalid packets | display filter `nanopb.validation == "dropped"` |
| find packets of one message | display filter on its fields, e.g. `nanopb.fleet.envelope.Envelope.version` |
| run without the GUI | the backend subcommands in the [reference](../tools/wireshark/README.md#command-line), e.g. `gen-c --protos-root P --out O` |

## Updating nanopb

The tools are kept apart from the nanopb library and from the validation
extension:

- No core nanopb file is changed. The tools don't touch `pb.h`,
  `pb_encode.*`, `pb_decode.*`, `pb_common.*` or `nanopb_generator.py`.
- The backend runs the generator the documented way: `generator/protoc` with
  the nanopb and nanopb-validate plugins. It merges the files they write.
- The dissector never calls nanopb. It reads a schema (`nanopb/schema.luadata`)
  that the backend builds from your protos.
- The installed plugin uses its own copy of nanopb (`nanopb/project/`), so
  updating this checkout changes nothing in Wireshark until you run
  `install-studio` again.

After updating nanopb, run `install-studio` again and then the tests below.
The places most likely to need attention after a big upstream change are:

- the validation extension (`generator/nanopb_validate_generator.py`), which
  reads the generator's internal message model;
- the backend's reading of nanopb's options (`max_size`, `max_count`, ...)
  through `nanopb.proto`.

If the generated file names or the `.options` format change, the tests show it
right away.

## Troubleshooting

| Symptom | Cause and fix |
|---------|---------------|
| No Tools > nanopb menu | The files aren't in the *Personal Lua Plugins* folder, or Lua failed to load them; look at Help > About Wireshark > Plugins. |
| "Backend did not run" | The Python in `nanopb/studio_config.luadata` is wrong, or is the Windows Store stub. Run `install-studio` again with the right Python. |
| `protoc failed` | Run the same backend subcommand in a terminal to see the whole error; check that `protobuf` and `grpcio-tools` are installed for that Python. |
| My protocol isn't in Decode As | Run **Load protos directory into Wireshark** again, then press Ctrl+Shift+L. The folder must contain at least one message of its own. |
| A packet has no Validation subtree | It wasn't decoded as nanopb: another dissector claimed it, or nothing maps its port. Use Decode As, the Protocol preference or the port map. |
| A packet is claimed by another protocol (e.g. KNXnet/IP) | The heuristics of other dissectors run on unmapped ports. Map the port with Decode As. |
| `pb_callback_t` in the generated header | A string, bytes or repeated field has no `max_size` / `max_count` in its `.options` file. |
| Wireshark is busy while generating | Generation runs in Python while Wireshark waits, about a second per protocol. Units are generated in parallel. |

## Testing the tools

The tests live in `tools/wireshark/tests`:

    python -m unittest discover -s tools/wireshark/tests -v
    python tools/wireshark/examples/stress/stress_test.py

- The Lua tests need `pip install lupa`.
- The real-Wireshark tests need `tshark`.
- The C checks need a C compiler, for example `pip install ziglang`.

A test that lacks its tool is skipped. For a manual check in Wireshark, follow
`tools/wireshark/tests/live/CHECKLIST.md`.
