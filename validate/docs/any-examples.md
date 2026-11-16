# `google.protobuf.Any` with many protos: worked example

A protocol folder with many `.proto` files, where messages travel inside `Any`
fields, inside other `Any` fields, inside oneofs and repeated fields. Everything
below is real: the files are `validate/examples/stress/protos/`, the C is what
`python -m nanopb_validate gen` writes for them, and every claim about drops is a
case in `validate/tests/py/test_filter_runtime.py`.

## 1. Is `Any` static? Yes.

`Any` is two fields, `type_url` and `value`. nanopb makes each one a fixed array
when it is given a size, and the tool always gives it one:

| Where the size comes from | type_url | value |
|---|---|---|
| Built in (`validate/nanopb_validate/wireshark_include/google/protobuf/any.options`) | 128 | 256 |
| Your own `google/protobuf/any.options` in the protos folder (this example) | 96 | 512 |

The generated struct, from `fleet.pb.h`:

```c
typedef PB_BYTES_ARRAY_T(512) fleet_google_protobuf_Any_value_t;
typedef struct _fleet_google_protobuf_Any {
    char type_url[96];
    fleet_google_protobuf_Any_value_t value;
} fleet_google_protobuf_Any;          /* 610 bytes, no pb_callback_t anywhere */
```

So no heap and no callbacks. The price of static is a limit: a `type_url` that does
not fit in `type_url`, or a payload bigger than `value`, cannot be decoded and the
packet is dropped (cases `type_url longer than its storage` and `payload bigger
than Any.value`). Size `value` for your largest message.

A `repeated Any` needs a count: give it `max_count` in the `.options` file
(`fleet/envelope.options`: `fleet.envelope.Batch.items max_count:3`). A field
without one would be a callback, and the filter generator refuses it with the
field's name instead of generating something that cannot inspect it.

## 2. The protocol

Seven `.proto` files, one protocol (`fleet`), one shared folder:

```
protos/
  google/protobuf/any.options        Any storage (96 / 512)
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

1. reads the `type_url` once: the hash and length of the name after the last `/`
   (any host prefix is accepted);
2. jumps to that message's `case`, confirms the name (length, then `memcmp`),
   decodes `value` into a struct and runs that message's validator (all its rules);
3. walks the decoded struct for further `Any` fields and repeats from 1 for each.

Anything else is dropped and logged through `PB_VALIDATE_FILTER_DROP`: an unknown
`type_url`, a message that does not decode, a rule that fails, more than
`PB_VALIDATE_FILTER_MAX_ANY_DEPTH` (default 4) Anys nested.

## 4. The generated filter: one function

The protocol is a single static function and the two entry points (nothing per
message). This is the whole shape of `fleet.pb.c`:

```c
static int fleet_check_any(const fleet_google_protobuf_Any *any, int depth);
int fleet_udp(void *ctx, const uint8_t *packet, size_t packet_size);
int fleet_tcp(void *ctx, const uint8_t *packet, size_t packet_size, bool is_to_server);
```

and its `switch` reads by message name, one line for a message without `Any` fields:

```c
    switch (hash) {
        case FLEET_HASH_FLEET_TYPES_VEC3:
            FLEET_FILTER_MESSAGE("fleet.types.Vec3", fleet_types_Vec3, pb_validate_fleet_types_Vec3);
            break;
        case FLEET_HASH_FLEET_CMD_SETMODE:
            FLEET_FILTER_MESSAGE("fleet.cmd.SetMode", fleet_cmd_SetMode, pb_validate_fleet_cmd_SetMode);
            break;
        ...
```

and, for a message that holds `Any` fields, the walk written out in place:

```c
        case FLEET_HASH_FLEET_ENVELOPE_BATCH:
            if (FLEET_NAME_IS("fleet.envelope.Batch")) {
                FLEET_NESTED_PAYLOAD(fleet_envelope_Batch);
                FLEET_DECODE("fleet.envelope.Batch", fleet_envelope_Batch, pb_validate_fleet_envelope_Batch);
                {
                    pb_size_t i0;
                    for (i0 = 0; i0 < payload->items_count; i0++) {
                        if (fleet_check_any(&payload->items[i0], depth + 1) != 0) return -1;
                    }
                }
                return 0;
            }
            break;
```

`Envelope` does the same with a `switch (payload->which_body)`, and the arm
`Envelope.frame` walks `Frame`'s `readings[]` and `primary` right there, so a
sub-message with an `Any` inside needs no function of its own.

## 5. Memory

Measured on this example (`sizeof`, 64-bit, `-std=c99`):

| | bytes |
|---|---|
| `Any` (96 + 512 + length) | 610 |
| `Imu` | 104 |
| `Batch` (3 × Any) | 1832 |
| `Frame` | 2672 |
| `Envelope` | 2720 |

By default a decoded payload lives on the stack, one per nesting level: at most
`PB_VALIDATE_FILTER_MAX_ANY_DEPTH` (4) of them at a time, so well under 4 × 2.7 KB
for this protocol. Build with `-DPB_VALIDATE_FILTER_STATIC_BUFFERS` to move them to
static storage (nothing large on the stack; the filter then is not reentrant). A
message that holds `Any` fields gets one static slot per nesting level, because it
can legitimately appear inside itself (a `Batch` in a `Batch`); a message that does
not gets one slot. The test builds the example both ways and runs the same packets.

To shrink: lower `Any.value` to your largest message, lower
`PB_VALIDATE_FILTER_MAX_ANY_DEPTH`, and `max_count` the repeated `Any` fields.

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
