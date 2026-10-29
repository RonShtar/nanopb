# Nanopb Validation

Nanopb validation provides declarative constraints for Protocol Buffer messages that are enforced through generated C validation code. This feature enables embedded systems to validate messages efficiently without heap allocation or runtime reflection.

## Overview

The validation feature allows you to:
- Define constraints directly in `.proto` files using custom options
- Generate C validation functions automatically
- Validate messages before encoding or after decoding
- Get detailed violation reports without dynamic memory allocation

## Enabling Validation

Validation code is produced by a separate protoc plugin,
`protoc-gen-nanopb-validate`. Running that plugin *is* the request for
validation - there is no `--validate` flag any more.

```bash
protoc   --nanopb_out=--protoc-insertion-points:.   --nanopb-validate_out=.   message.proto
```

This writes the usual `message.pb.h` / `message.pb.c`, plus
`message_validate.h` / `message_validate.c`.

Two things are required and easy to get wrong:

* `--nanopb_out` must come **before** `--nanopb-validate_out`. protoc runs
  generators in command line order, and the validate plugin injects into the
  files nanopb produced.
* nanopb must be given `--protoc-insertion-points`, otherwise there are no
  markers to inject into.

Options that affect C naming (`-C`, `--custom-style`, `-s`, `-f`, `-I`, `-x`)
must be passed to **both** plugins, since the validate plugin rebuilds nanopb's
view of the file in order to see the same mangled type names.

> **Note:** `validate.proto` declares a file-level `option (validate.validate)`,
> which is read but has no effect on generation (there is no way to disable
> validation for a file that has already been routed through this plugin).
> The message-level `validate.message` extension (`requires`/`mutex`/`at_least`,
> see below) is read, but not yet enforced -- using it is a **generation-time
> error** rather than a silent no-op, so it can't be mistaken for working. The
> same is true for a handful of field-level options; see
> [Unimplemented Options](#unimplemented-options).

## Field-Level Constraints

### Numeric Constraints

```protobuf
message Product {
    // Basic numeric constraints
    int32 quantity = 1 [
        (validate.rules).int32.gte = 0,      // Greater than or equal
        (validate.rules).int32.lte = 1000    // Less than or equal
    ];
    
    // Exact value constraint
    int32 version = 2 [(validate.rules).int32.const = 1];
    
    // Value must be in list
    int32 status = 3 [(validate.rules).int32.in = [1, 2, 3]];
    
    // Value must not be in list
    int32 type = 4 [(validate.rules).int32.not_in = [99, 100]];
}
```

Supported for: `int32`, `int64`, `uint32`, `uint64`, `sint32`, `sint64`, `fixed32`, `fixed64`, `sfixed32`, `sfixed64`, `float`, `double`

### String Constraints

```protobuf
message User {
    // Length constraints
    string username = 1 [
        (validate.rules).string.min_len = 3,
        (validate.rules).string.max_len = 20
    ];
    
    // Pattern matching
    string email = 2 [
        (validate.rules).string.contains = "@",
        (validate.rules).string.suffix = ".com"
    ];
    
    // ASCII only
    string id = 3 [(validate.rules).string.ascii = true];
    
    // Exact match or in list
    string role = 4 [(validate.rules).string.in = ["admin", "user", "guest"]];
}
```

**Note**: String length constraints only work when strings are generated as static arrays (using `max_size` option). Callback-based strings skip length validation.

### Bytes Constraints

```protobuf
message Data {
    // Length constraints
    bytes payload = 1 [
        (validate.rules).bytes.min_len = 10,
        (validate.rules).bytes.max_len = 1024
    ];
    
    // Prefix/suffix matching
    bytes header = 2 [(validate.rules).bytes.prefix = "\x00\x01\x02"];
}
```

### Enum Constraints

```protobuf
enum Status {
    UNKNOWN = 0;
    ACTIVE = 1;
    INACTIVE = 2;
}

message Record {
    // Ensure enum value is defined (default: true)
    Status status = 1 [(validate.rules).enum.defined_only = true];
    
    // Restrict to subset of values
    Status filtered = 2 [(validate.rules).enum.in = [1, 2]];
}
```

### Repeated Field Constraints

```protobuf
message Collection {
    // Item count constraints
    repeated string items = 1 [
        (nanopb).max_count = 100,  // Required for static allocation
        (validate.rules).repeated.min_items = 1,
        (validate.rules).repeated.max_items = 50
    ];
    
    // Unique items only
    repeated int32 ids = 2 [(validate.rules).repeated.unique = true];
}
```

### Required Fields

```protobuf
message Config {
    // Make optional field required for validation
    optional string name = 1 [(validate.rules).required = true];
}
```

`oneof_required` (require a specific oneof arm to be selected) is declared in
`validate.proto` but not yet enforced -- see
[Unimplemented Options](#unimplemented-options).

## Message-Level Constraints

**Not yet enforced.** `requires`, `mutex`, and `at_least` are fully declared
in `validate.proto`, are read off the message descriptor, and appear in
generated header comments -- but generation fails with a clear error naming
the message and option if any of them are actually used, rather than
silently producing a validator that doesn't check them. See
[Unimplemented Options](#unimplemented-options). The shapes below are what
the options will look like once support lands.

### Field Dependencies

```protobuf
message Address {
    string city = 1;
    string state = 2;
    string country = 3;
    
    // If city is set, state must also be set
    option (validate.message).requires = "state";
}
```

### Mutual Exclusion

```protobuf
message Settings {
    bool use_default = 1;
    string custom_value = 2;
    
    // Only one of these fields can be set
    option (validate.message).mutex = {
        fields: ["use_default", "custom_value"]
    };
}
```

### At Least N Fields

```protobuf
message Contact {
    string email = 1;
    string phone = 2;
    string address = 3;
    
    // At least 2 contact methods required
    option (validate.message).at_least = {
        n: 2
        fields: ["email", "phone", "address"]
    };
}
```

## Using Generated Validation Code

### Basic Validation

```c
#include "message.pb.h"
#include "message_validate.h"

void validate_example() {
    MyMessage msg = MyMessage_init_zero;
    pb_violations_t violations;
    
    // Initialize violations collector
    pb_violations_init(&violations);
    
    // Validate the message
    if (!pb_validate_MyMessage(&msg, &violations)) {
        // Handle validation errors
        for (size_t i = 0; i < violations.count; i++) {
            printf("Validation error: %s - %s: %s\n",
                   violations.violations[i].field_path,
                   violations.violations[i].constraint_id,
                   violations.violations[i].message);
        }
    }
}
```

### Validation Hooks

Enable automatic validation during encode/decode:

```c
// In your build configuration or source file:
#define PB_VALIDATE_BEFORE_ENCODE
#define PB_VALIDATE_AFTER_DECODE

// Then use the validation-aware macros:
pb_ostream_t stream = ...;
if (!pb_validate_encode(&stream, MyMessage, &msg)) {
    // Validation or encoding failed
}

pb_istream_t stream = ...;
if (!pb_validate_decode(&stream, MyMessage, &msg)) {
    // Decoding or validation failed
}
```

## Configuration Options

### Compile-Time Settings

```c
// Maximum number of violations to collect (default: 16)
#define PB_VALIDATE_MAX_VIOLATIONS 32

// Stop validation on first error (default: 1)
#define PB_VALIDATE_EARLY_EXIT 0

// Maximum length for field paths in violations (default: 128)
#define PB_VALIDATE_MAX_PATH_LENGTH 256

// Maximum simultaneous field/index nesting depth ("a.b[2].c" is depth 3)
// tracked while validating (default: 16)
#define PB_VALIDATE_MAX_PATH_DEPTH 32

// Packet filters decode into static structs instead of the stack
// (less stack; the filter is then not reentrant). Default: off.
#define PB_VALIDATE_FILTER_STATIC_BUFFERS
```

A validator can be called with `NULL` instead of a `pb_violations_t`: it then
only answers pass/fail, skips all path bookkeeping and is noticeably faster.
The generated packet filters do this unless `PB_VALIDATE_DEBUG` is defined.
See [Validation performance](validation_performance.md) for measurements.

### Debug Mode

`PB_VALIDATE_DEBUG` is a single compile-time switch between two behaviors.
Generated `*_validate.c`/`.h` files are identical either way -- only what
`pb_validate.h`'s macros expand to changes, so picking a mode is purely a
build-time decision, not a generation-time one.

```c
#define PB_VALIDATE_DEBUG
```

| | Undefined (default) | Defined |
|---|---|---|
| Violations per call | Stops at the first one, per `PB_VALIDATE_EARLY_EXIT` (ignored when set to 0, but the default is to stop) | Always collects every violation on the message, regardless of `PB_VALIDATE_EARLY_EXIT` |
| `field_path` | Materialized only when a violation is about to be recorded; no string work on the passing path | Same |
| `message` | Static string literal (zero-copy `const char *`) | Owned buffer; numeric and string-length rules interpolate the actual/expected value, e.g. `"Value constraint failed (got 200, expected 150)"` |
| Packet filters (`pkg_Msg_filter_udp`/`filter_tcp`) | Reject with `-1`, no diagnostics | Also call the pluggable `PB_VALIDATE_FILTER_LOG(fmt, ...)` hook (default no-op; define your own before including the generated filter code to route rejections to your logger) with why each packet was rejected |

Turning `PB_VALIDATE_DEBUG` on grows `sizeof(pb_violations_t)`, since each
violation gets its own owned `field_path`/`message` buffers instead of a
zero-copy pointer to a string literal -- expected for a debug build, not
meant for the same memory budget as production.

### Generator Options

Passed via `--nanopb-validate_opt=` (or before the `:` in
`--nanopb-validate_out=`):

- `--filter=NAME`: Fully qualified name of the *protocol entrypoint* message,
  e.g. `my_package.BaseMessage`. This is the only option that turns filter
  generation on. Without it the plugin emits validators and nothing else.
  Several entrypoints can be listed separated by `;`
  (`--filter=pkg.Command;pkg.Status`). Each one gets its own pair of filter
  functions, injected into the `.pb.c`/`.pb.h` of the file that defines it.
  Every listed message must be defined in a file generated by the same
  invocation. With more than one entrypoint, `--filter-mode` and
  `--filter-payloads` cannot be given.
- `--filter-mode=auto|single|oneof|any`: How packets are identified.
  `auto` (default) derives this from the entrypoint's descriptor. Giving the
  mode explicitly *asserts* it: generation fails if the schema does not have
  the required shape. Use `single` to decode every packet as the entrypoint
  itself even when it declares a oneof or carries an `Any`.
- `--filter-payloads=A;B;C`: Fully qualified payload types allowed inside a
  `google.protobuf.Any` entrypoint, separated by `;`. Overrides the
  `(validate.rules).any.in` allow-list. (`,` cannot be used as a separator
  because protoc already uses it to separate plugin options.)

#### What you must declare, and what is derived

The filter is a security boundary, so nothing about the protocol shape is
guessed. You name the entrypoint; everything structurally present in the
descriptors is derived from them:

| Derived automatically | Must be declared |
|---|---|
| That a field is `google.protobuf.Any` (exact type match) | Which message is the entrypoint (`--filter`) |
| That the entrypoint has a oneof, its arms and their message types | The `Any` allow-list (`any.in` or `--filter-payloads`) |
| Fully qualified `type_url`s, nested and imported types included | Anything the schema leaves ambiguous |
| Whether each payload type has a validator to call | |

Anything ambiguous is a **generation error**, never a pick. That includes an
entrypoint with more than one oneof, more than one `Any` field, both an `Any`
and a oneof, a repeated `Any`, an `Any` with no allow-list (a `not_in`
deny-list cannot produce a dispatch table), or an allow-list entry naming a
message that is not in the compiled descriptors. Each error names the
conflicting fields and the option that resolves it.

Note that an *opcode enum* alongside the payload oneof is not used for
dispatch. The oneof tag on the wire is authoritative; correlating an enum to
oneof arms by name is a guess, and a wrong guess routes a packet to the wrong
validator. Constrain the opcode with an ordinary rule such as
`(validate.rules).enum.defined_only = true` and it is checked when the
entrypoint is validated, before any payload is inspected.

#### Generated API

For `--filter=my_package.BaseMessage` the plugin injects into the `.pb.h`:

```c
int my_package_BaseMessage_filter_udp(void *ctx, const uint8_t *packet,
                                      size_t packet_size);
int my_package_BaseMessage_filter_tcp(void *ctx, const uint8_t *packet,
                                      size_t packet_size, bool is_to_server);
```

Both return `0` to allow the packet and `-1` to reject it, and both are thin
wrappers over one transport-independent static core, so the filtering logic is
not coupled to UDP or TCP. Symbols are namespaced by the entrypoint message, so
several filtered `.proto` files can be linked into one binary.

The filter decodes, validates the entrypoint, identifies the payload, decodes
and validates it, and rejects anything it cannot account for -- an undecodable
buffer, an unset or unknown oneof arm, an absent payload, or a `type_url` that
is not on the allow-list.

#### Examples

`google.protobuf.Any` carries a string and a bytes field, and nanopb turns both
into `pb_callback_t` unless an `.options` file gives them a `max_size`. The
filter reads them directly, so an `Any` entrypoint needs, alongside your
`.proto`:

```
google.protobuf.Any.type_url max_size:128
google.protobuf.Any.value    max_size:512
```

sized for your protocol. Without it the injected filter will not compile. The
plugin cannot check this for you: `google/protobuf/any.pb.h` is produced by a
separate protoc invocation whose options this plugin does not see.

`Any` tunnel, allow-list taken from the schema:

```protobuf
message BaseMessage {
  google.protobuf.Any payload = 1 [
    (nanopb).max_size = 512,
    (validate.rules).any.in = "type.googleapis.com/my_package.Login",
    (validate.rules).any.in = "type.googleapis.com/my_package.Telemetry"
  ];
}
```

    --nanopb-validate_opt=--filter=my_package.BaseMessage

Same, with the allow-list pinned in the build instead:

    --nanopb-validate_opt=--filter=my_package.BaseMessage,--filter-payloads=my_package.Login;my_package.Telemetry

`oneof` tunnel (with or without an opcode field alongside it):

    --nanopb-validate_opt=--filter=my_package.BaseMessage

Single fixed message -- every packet is this type:

    --nanopb-validate_opt=--filter=my_package.Foo

...and to force that even when `Foo` declares a oneof you would otherwise
dispatch on:

    --nanopb-validate_opt=--filter=my_package.Foo,--filter-mode=single

Apply `--filter` only to the invocation that compiles the `.proto` defining the
entrypoint. If the named message is not in the descriptors the plugin was
given, generation fails rather than silently producing no filter.

## Limitations

1. **No Regex Support**: Pattern matching is limited to simple string operations (contains, prefix, suffix)
2. **Callback Fields**: `pb_callback_t` fields are not validated at all.
   Validation applies to statically allocated fields (`POINTER` allocation
   included); give strings, bytes and repeated fields a `max_size`/`max_count`
   so they are not converted to callbacks
3. **No Heap Usage**: All validation data structures are statically allocated
4. **Proto3 Only**: Currently only supports proto3 syntax

### Unimplemented Options

These options are declared in `validate.proto`, parsed, and (for the
message-level ones) documented above -- but have no C-runtime enforcement
yet. Using any of them is a **generation-time error** naming the offending
message/field and option, not a silently-ignored no-op:

- `(validate.message).requires`, `.mutex`, `.at_least` -- message-level
  cross-field constraints
- `(validate.rules).oneof_required` -- require a specific oneof arm
- `(validate.rules).repeated.map.no_sparse`
- `(validate.rules).string.pattern`, `(validate.rules).bytes.pattern` -- no
  regex engine
- `(validate.rules).string.min_bytes`, `.max_bytes`

Remove the option from the `.proto` (or wait for the option to gain support)
if generation fails citing one of these.

## Integration with Build Systems

### Make
`PROTOC_POST_OPTS` is appended after `--nanopb_out`, which is what keeps the
plugin ordering correct:

```makefile
PROTOC_OPTS      += --nanopb_opt=--protoc-insertion-points
PROTOC_POST_OPTS += --nanopb-validate_out=.
```

### CMake
Define `NANOPB_VALIDATE_OPTIONS` to switch the plugin on. An empty string means
"validate, with no special envelope handling"; `NANOPB_OPTIONS` are forwarded to
the plugin automatically.

```cmake
set(NANOPB_VALIDATE_OPTIONS "")
nanopb_generate_cpp(PROTO_SRCS PROTO_HDRS message.proto)
```

### Bazel
Not currently supported. `cc_nanopb_proto_library` builds its outputs with a
single `proto_common.compile()` action and one plugin, so running a second
plugin that injects into nanopb's output would need a separate toolchain plus
declared `_validate.h`/`_validate.c` outputs.

## Performance Considerations

- Rule data is stored in const arrays in program memory
- No dynamic memory allocation during validation
- Field paths are tracked as a small fixed-size stack of pointers/indices
  while validating (`PB_VALIDATE_MAX_PATH_DEPTH`); the dotted/bracketed
  `field_path` string is only ever materialized at the moment a violation is
  actually recorded, so passing fields cost no string work at all
- By default (`PB_VALIDATE_DEBUG` undefined), validation stops at the first
  violation per `PB_VALIDATE_EARLY_EXIT` (default on) and violation messages
  are zero-copy string literals
- Define `PB_VALIDATE_DEBUG` to force collecting every violation and get
  value-interpolated messages -- see [Debug Mode](#debug-mode). This is a
  compile-time tradeoff (more RAM per violation, no early exit), meant for
  development/debugging builds rather than production
- Pass `NULL` as the violations buffer where only pass/fail matters; the
  generated packet filters do. [Validation performance](validation_performance.md)
  walks through the hot path, the measured cost of each part and the
  compile-time switches that matter (`PB_BUFFER_ONLY`, `PB_NO_ERRMSG`,
  `PB_VALIDATE_FILTER_STATIC_BUFFERS`, ...)

## Error Messages

Validation errors include:
- `field_path`: Dotted path to the field (e.g., "user.email"). An owned copy
  made at the moment the violation is recorded, so it stays valid for as long
  as the `pb_violations_t` you passed in does -- note that nested-message
  validation is a separate call with its own path tracking, so a violation
  inside a submessage reports its path relative to that submessage (e.g.
  `"email"`, not `"user.email"`)
- `constraint_id`: Type of constraint violated (e.g., "string.min_len")
- `message`: Human-readable error description. A static string literal by
  default; under `PB_VALIDATE_DEBUG`, numeric and string-length rules
  interpolate the actual/expected values (see [Debug Mode](#debug-mode))

Example violations:
```
user.email: string.contains - Field must contain '@'
user.age: int32.gte - Value must be >= 0
items[2]: string.max_len - String exceeds maximum length of 50
```

Under `PB_VALIDATE_DEBUG`, the last one instead reads something like:
```
items[2]: string.max_len - String too long (got 62, expected 50)
```
