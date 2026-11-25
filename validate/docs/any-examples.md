# `google.protobuf.Any` with many protos: worked example

A protocol folder with many `.proto` files, where messages travel inside `Any`
fields, inside other `Any` fields, inside oneofs and repeated fields. Everything
below is real: the files are `validate/examples/stress/protos/`, the C is what
`python -m nanopb_validate gen` writes for them, and every claim about drops is a
case in `validate/tests/py/test_filter_runtime.py`.

## 1. Is `Any` static? Yes.

`Any` is two fields, `type_url` and `value`. nanopb makes each one a fixed array
when it is given a size, and the tool always gives both one:

| | size | from |
|---|---|---|
| `type_url` | exactly the longest URL the protocol can carry, plus the NUL | computed by `gen` per protocol: `type.googleapis.com/` + the longest full name of every message in the protocol's files and imports (nested ones too), or a longer `any.in` URL |
| `value` | the largest maximum encoded size nanopb computes (`#define <msg>_size`) of any message, with the `Any`s inside it holding the largest message that has none: one level of `Any` always fits | computed by `gen` per protocol (two nanopb runs); `--any-value-size N` sets it |

`gen` prints the result per protocol:

```
fleet -> out/fleet
  Any.type_url: char[49], the longest URL + NUL (type.googleapis.com/fleet.telemetry.Health.Fault)
  Any.value: 1053 bytes, fleet.envelope.Envelope (fleet_envelope_Envelope_size) with its Anys
             holding the largest message without an Any, fleet.sensors.Imu
  note: Any.value (1053 bytes) fits every message with one level of Any;
        fleet.envelope.Batch.items, fleet.envelope.Envelope.extension, fleet.telemetry.Frame.readings
        can hold a message that carries an Any itself (no any.in, or any.in allows one), which fits
        only when encoded that small: set --any-value-size for deeper nesting
  largest packet: FLEET_MAX_SIZE = fleet_google_protobuf_Any_size (1106 bytes)
```

and the generated struct, from `fleet.pb.h`:

```c
typedef PB_BYTES_ARRAY_T(1053) fleet_google_protobuf_Any_value_t;
typedef struct _fleet_google_protobuf_Any {
    char type_url[49];
    fleet_google_protobuf_Any_value_t value;
} fleet_google_protobuf_Any;          /* 1106 bytes, no pb_callback_t anywhere */

#define FLEET_MAX_SIZE 4806     /* the largest packet: type_url + fleet_envelope_Envelope_size + framing */
```

So no heap and no callbacks. The packet itself (the outer `Any`) is read in place,
straight from the receive buffer: no `Any` struct is filled and nothing is copied, so
the packet can be as large as the largest message (`<PROTOCOL>_MAX_SIZE`, e.g. a 3 KB
`Batch`, more than one Ethernet MTU). The static limit applies to an `Any` *inside* a
message: its `type_url` and `value` arrays. Every message fits by construction when the `Any`s
inside it hold messages without an `Any` (one level). Deeper (an `Envelope` in a `Batch` in
a `Batch`) has no fixed maximum, so it fits only when its encoding is at most `value`
(`test_filter_runtime.py` checks both). For a protocol like yours, `Packet { Any payload }`
with `any.in` naming only plain messages, one level is all there is, and there is no note:
`camera` gets `value` 99 bytes, exactly `camera.Packet` holding the largest `camera.Frame`.

**No callbacks, no malloc, anywhere.** `gen` refuses to write a protocol in which any
field would be a `pb_callback_t` (a string, bytes, repeated field or map without
`max_size`/`max_count`) or a pointer (nanopb's `FT_POINTER`, which needs malloc), and
names each field:

```
error: fleet: 1 field(s) would not be static storage (CALLBACK = pb_callback_t, POINTER = malloc):
  fleet_envelope_Batch.items: CALLBACK repeated message
Give each a size in a .options file next to its .proto, for example ...
```

So a `repeated Any` needs a count (`fleet/envelope.options`:
`fleet.envelope.Batch.items max_count:3`). `--allow-callbacks` turns the check off.

## 2. The protocol

Seven `.proto` files, one protocol (`fleet`), one shared folder:

```
protos/
  google/protobuf/any.options        Any.value storage (512); type_url is computed
  fleet/types.proto                  Vec3, GeoPoint, DeviceId, Version, Severity
  fleet/sensors.proto                Imu, Battery, Gps
  fleet/commands.proto               Move, Stop, SetMode, Command (oneof of those)
  fleet/status.proto                 Status (proto2: required, unpacked)
  fleet/telemetry.proto              Frame: repeated Any readings, optional Any primary
  fleet/envelope.proto               Envelope (oneof incl. Any), Batch (repeated Any)
  shared/units.proto                 Quantity, imported by sensors.proto
```

Where `Any` appears:

```proto
message Batch {                                   // envelope.proto
    repeated google.protobuf.Any items = 1 [(validate.rules).repeated = {max_items: 3}];
}

message Envelope {
    fleet.types.Version version = 1 [(validate.rules).required = true];
    oneof body {
        fleet.telemetry.Frame frame = 2;          // has Any inside
        fleet.cmd.Command command = 3;
        fleet.status.Status status = 4;
        google.protobuf.Any extension = 5;        // an Any as a oneof arm
        Batch batch = 6;                          // Any inside, so Any in Any
    }
    ...
}

message Frame {                                   // telemetry.proto
    ...
    repeated google.protobuf.Any readings = 4 [(validate.rules).repeated = {max_items: 3}];
    google.protobuf.Any primary = 7 [             // allow-list on the type_url
        (validate.rules).any.in = "type.googleapis.com/fleet.sensors.Imu",
        (validate.rules).any.in = "type.googleapis.com/fleet.sensors.Battery",
        (validate.rules).any.in = "type.googleapis.com/fleet.sensors.Gps"
    ];
}
```

## 3. A packet, and what the filter does with it

The packet is an `Any` whose `type_url` names the message inside. This one is four
Anys deep:

```
Any  type_url = ".../fleet.envelope.Envelope"                 level 0
 └ Envelope.batch (oneof arm)
    └ Batch.items[0] = Any ".../fleet.envelope.Batch"         level 1
       └ Batch.items[0] = Any ".../fleet.envelope.Envelope"   level 2
          └ Envelope.extension = Any ".../fleet.cmd.SetMode"  level 3
```

For each level the filter:

1. finds the message the `type_url` names: `pb_filter_find_route()` (in `pb_validate.c`)
   takes the name after the last `/` (any host prefix is accepted), hashes it and looks it
   up in the protocol's route table by binary search, confirming the name;
2. calls that message's check function: `pb_decode` of `value` into the message's struct,
   then the message's validator (all its rules);
3. walks the decoded struct for further `Any` fields and repeats from 1 for each.

Anything else is dropped and logged through `PB_VALIDATE_FILTER_DROP`: an unknown
`type_url`, a message that does not decode, a rule that fails, more than
`PB_VALIDATE_FILTER_MAX_ANY_DEPTH` (default 4) Anys nested.

## 4. The generated filter

`fleet.pb.c` holds the descriptors, then the filter: plain functions, no macros and no
decoder of its own. Decoding is nanopb's `pb_decode`, the outer `Any` and the lookup are
`pb_validate.c`'s `pb_filter_read_any()` and `pb_filter_find_route()`.

One check function per message. A message without `Any` fields decodes and validates:

```c
static int fleet_check_cmd_SetMode(const pb_byte_t *value, size_t value_size, int depth)
{
    fleet_cmd_SetMode msg;   /* static with PB_VALIDATE_FILTER_STATIC_BUFFERS */
    pb_istream_t stream = pb_istream_from_buffer(value, value_size);

    if (!pb_decode(&stream, fleet_cmd_SetMode_fields, &msg)) {
        PB_VALIDATE_FILTER_DROP("fleet", "cannot decode fleet.cmd.SetMode");
        return -1;
    }
    if (!fleet_validate_cmd_SetMode(&msg, NULL)) {
        PB_VALIDATE_FILTER_DROP("fleet", "fleet.cmd.SetMode validation failed");
        return -1;
    }
    (void)depth;
    return 0;
}
```

A message that holds `Any` fields then checks the message inside each of them:

```c
static int fleet_check_envelope_Batch(const pb_byte_t *value, size_t value_size, int depth)
{
    fleet_envelope_Batch level;   /* one static struct per level with STATIC_BUFFERS */
    fleet_envelope_Batch *msg = &level;
    pb_istream_t stream = pb_istream_from_buffer(value, value_size);

    if (!pb_decode(&stream, fleet_envelope_Batch_fields, msg)) { ... return -1; }
    if (!fleet_validate_envelope_Batch(msg, NULL)) { ... return -1; }

    {
        pb_size_t i0;
        for (i0 = 0; i0 < msg->items_count; i0++) {
            if (fleet_check_any_field(&msg->items[i0], depth + 1) != 0) return -1;
        }
    }
    return 0;
}
```

`Envelope` does the same with a `switch (msg->which_body)`, and the arm `Envelope.frame`
walks `Frame`'s `readings[]` and `primary` right there, so a sub-message with an `Any`
inside needs no function of its own.

The route table names every message once, sorted by the hash of its name:

```c
static const pb_filter_route_t fleet_routes[] = {
    { 0x19f628c5u, "fleet.cmd.Move",               fleet_check_cmd_Move },
    { 0x19f8f4f6u, "fleet.cmd.Stop",               fleet_check_cmd_Stop },
    ...
    { 0xf7056ba3u, "fleet.types.Version",          fleet_check_types_Version },
};
```

and the rest is the dispatch and the two entry points:

```c
static int fleet_check_any(const char *type_url, size_t type_url_size,
                           const pb_byte_t *value, size_t value_size, int depth)
{
    const pb_filter_route_t *route;

    if (depth >= PB_VALIDATE_FILTER_MAX_ANY_DEPTH) { ... return -1; }
    route = pb_filter_find_route(fleet_routes, sizeof(fleet_routes) / sizeof(fleet_routes[0]),
                                 type_url, type_url_size);
    if (route == NULL) { ... return -1; }
    return route->check(value, value_size, depth);
}

int fleet_udp(void *ctx, const uint8_t *packet, size_t packet_size)
{
    pb_filter_any_t any;

    (void)ctx;
    if (!pb_filter_read_any(packet, packet_size, &any)) { ... return -1; }
    return fleet_check_any(any.type_url, any.type_url_size, any.value, any.value_size, 0);
}
```

## 5. Memory

Measured on this example (`sizeof`, 64-bit, `-std=c99`):

| | bytes |
|---|---|
| | default (one level of `Any` always fits) | `--any-value-size 512` |
|---|---|---|
| `Any` | 1106 (49 + 1053 + length) | 564 |
| `Imu` | 104 | 104 |
| `Batch` (3 × Any) | 3320 | 1694 |
| `Frame` (4 × Any) | 4656 | 2488 |
| `Envelope` | 4704 | 2536 |

This protocol is the expensive case: its `Frame` alone carries four `Any`s, so the size that
always fits is large. `--any-value-size` trades the guarantee for RAM.

(With the earlier fixed `type_url[96]` and `value` 512 an `Any` was 610 bytes.)

By default a decoded payload lives on the stack, one per nesting level: at most
`PB_VALIDATE_FILTER_MAX_ANY_DEPTH` (4) of them at a time
for this protocol. Build with `-DPB_VALIDATE_FILTER_STATIC_BUFFERS` to move them to
static storage (nothing large on the stack; the filter then is not reentrant). A
message that holds `Any` fields gets one static slot per nesting level, because it
can legitimately appear inside itself (a `Batch` in a `Batch`); a message that does
not gets one slot. The test builds the example both ways and runs the same packets.

To shrink: lower the `max_count` of the repeated `Any` fields (it multiplies the size that
always fits), `PB_VALIDATE_FILTER_MAX_ANY_DEPTH`, or set `--any-value-size` and accept that
bigger packets are dropped.

## 6. Try it

```
python -m nanopb_validate check examples/stress/protos
python -m nanopb_validate gen   examples/stress/protos --out out --with-runtime
python -m nanopb_validate test --py            # includes test_filter_runtime.py
python examples/stress/stress_test.py          # C round trip + Wireshark dissection of every message
```

`test_filter_runtime.py` sends 23 packets through `fleet_udp`/`fleet_tcp` in both
builds, among them: an `Any` in a oneof, a bad item inside `Frame.readings`, a
`primary` outside its `any.in` list, a `Batch` in a `Batch` followed by an unknown
item (which a shared buffer would let through), exactly four Anys nested (allowed)
and five (dropped).

## 7. Several protocols, one program

The camera / gps / motor layout (one folder per protocol, each with its own
`.proto` files) generates one filter per protocol, `camera_udp`, `gps_udp`,
`motor_udp`, and puts what they share, with `--with-runtime` also the nanopb runtime,
once in `common/`, so all of them link into one program. See `validate/README.md`.
