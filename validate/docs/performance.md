# Validation performance

What a validated packet costs, which parts of it matter, and the
compile-time switches that change it. All numbers come from
`validate/tests/c/validate_benchmark` (see [Measuring](#measuring)); run it on your own
target, since the ratios carry over better than the absolute times.

## Where the time goes

A packet filter generated with `--filter=pkg.Envelope` does, per packet:

1. **`pb_decode` of the entrypoint** into a struct. This is the largest part:
   cost grows with the bytes in the packet and the number of fields, and is
   governed by the nanopb options below. It also uses most of the stack
   (about 2 KB in the benchmark, for nanopb's field iterators and stream).
2. **`pb_validate_<Envelope>()`**, which recurses into sub-messages, repeated
   sub-messages and the selected oneof arm. Each rule is a comparison, a
   `strlen`-based string check or a short loop (email, hostname, IP). On a
   passing packet every rule runs once; with early exit (the default) a
   failing packet stops at its first violation.
3. **Dispatch**: for a oneof entrypoint, a `switch` on `which_<oneof>`; for an
   `Any` entrypoint, a rolling hash of `type_url` plus one `strcmp`, then
   `pb_decode` and validation of the payload.

Costs that used to be on this path and no longer are:

- The filter used to fill a `pb_violations_t` (2.3 KB: 16 entries with a
  128-byte path each) on every packet. Release builds now pass `NULL`, so a
  validator only answers pass/fail and keeps no path stack.
- `<Msg>_init_zero` was copied into the decode structs before `pb_decode`,
  which initializes every field anyway.
- With oneof dispatch, the selected arm was validated twice: once by the
  entrypoint validator and once by the dispatch.

## Measured

`validate/tests/c/validate_benchmark`, a 124-byte `Envelope { version, oneof body:
Telemetry { device, seq, 8 x Reading { sensor, value, unit }, contact } }`,
`-O2`, x86-64, zig cc 21 (clang). `bad_first` breaks the first rule checked,
`bad_last` the last one.

Default build, ns per packet:

| operation | valid | bad_first | bad_last | peak stack |
|---|---|---|---|---|
| `pb_decode` only | 1140 | 1179 | 1125 | 2040 B |
| `pb_decode` + `pb_validate_Envelope(&msg, &violations)` | 1616 | 1481 | 1620 | 4360 B |
| `pb_decode` + `pb_validate_Envelope(&msg, NULL)` | 1238 | 1148 | 1208 | 2040 B |
| `Envelope_filter_udp()` | 1245 | 1163 | 1219 | 2088 B |
| `Envelope_filter_udp()` before inline compares (below) | 1350 | 1143 | 1319 | 2088 B |

So on this schema validation adds under 10% on top of decoding when it only
has to answer pass/fail, and about 40% when it fills a violations buffer.

Numeric comparisons, string length / prefix checks and item index tracking
are inline in the check macros (`PB_VALIDATE_COMPARE`,
`pb_validate_string_inline`, `PB_VALIDATE_PUSH_INDEX`): the rule type is a
constant in generated code, so a check folds to one compare with no call, and
index paths are only tracked when a violations buffer is collecting. That
halved the validation part (about 200 ns to 100 ns per packet here) and made
the generated validators 4% smaller at `-Os`.

The filter (valid packet) per build configuration:

| configuration | ns | peak stack |
|---|---|---|
| default | 1245 | 2088 B |
| `PB_BUFFER_ONLY` + `PB_NO_ERRMSG` | 984 | 1984 B |
| `PB_VALIDATE_FILTER_STATIC_BUFFERS` | 1315 | 1832 B |
| `PB_VALIDATE_DEBUG` | 2065 | 8376 B |

`validate/tests/py/test_performance.py` runs this benchmark and fails if
the filter costs more than 1.25 x decoding, if dropping costs more than
accepting, or if stack use grows past its budget.

## Switches

Defines must be the same for every file of a build (they change struct
layouts), so set them on the compiler command line or in a common header
included before `pb.h`.

Validation (`pb_validate.h`):

| define | default | effect |
|---|---|---|
| `PB_VALIDATE_EARLY_EXIT` | 1 | Stop at the first violation. 0 runs every rule even after a failure. |
| `PB_VALIDATE_DEBUG` | off | Collect every violation with value-formatted messages; filters log rejections through `PB_VALIDATE_FILTER_LOG`. About 1.6x slower and 4x the stack in the benchmark. Development builds only. |
| `PB_VALIDATE_MAX_VIOLATIONS` | 16 | Entries in `pb_violations_t`. Its size is roughly this times `PB_VALIDATE_MAX_PATH_LENGTH`; only matters when you pass a buffer. |
| `PB_VALIDATE_MAX_PATH_LENGTH` | 128 | Bytes for one violation's field path. Set it to your longest dotted path + 1. |
| `PB_VALIDATE_MAX_PATH_DEPTH` | 16 | Path segments tracked while validating with a buffer. Set it to your deepest nesting (fields + array indexes; a map with `keys`/`values` rules needs 3: `counts`, `[i]`, `key`). |
| `PB_VALIDATE_FILTER_STATIC_BUFFERS` | off | Filters decode into `static` structs instead of the stack. Saves the size of the entrypoint (and `Any` payload) struct per call, but the filter is then not reentrant: do not call the same filter from two threads or from an interrupt. |
| `PB_VALIDATE_FILTER_LOG(fmt, ...)` | no-op | Filter logging hook (printf-style). Receives one line per dropped packet in every build, plus every violated rule with `PB_VALIDATE_DEBUG`. |
| `PB_VALIDATE_FILTER_DROP(filter, reason)` | one line via `PB_VALIDATE_FILTER_LOG` | Called once per dropped packet, on the reject path only; accepted packets never pay for it. |
| `PB_VALIDATE_FILTER_MAX_ANY_DEPTH` | 4 | Protocol filters (`--protocol-filter`): levels of `Any` resolved inside each other. Each level keeps one decoded payload struct on the stack; `PB_VALIDATE_FILTER_STATIC_BUFFERS` only moves the outermost `Any` to static storage. |

nanopb (`pb.h`, see [reference](reference.md#compilation-options)):

| define | effect on validated decoding |
|---|---|
| `PB_BUFFER_ONLY` | Decode from memory buffers only (no stream callbacks). The biggest single speedup for filters: about 20% here. |
| `PB_NO_ERRMSG` | No error strings; smaller code, slightly faster. Filters only use the return value anyway. |
| `PB_WITHOUT_64BIT` | No 64-bit integer support; faster on 8/16-bit MCUs. Only possible if the schema has no 64-bit fields. |
| `PB_FIELD_32BIT` | Needed for large tags, fields or arrays (the generator tells you); makes descriptors larger and decoding slightly slower. |
| `PB_VALIDATE_UTF8` | pb_decode checks that strings are UTF-8: extra cost per string byte. Independent of validate.proto rules. |
| `PB_ENABLE_MALLOC` | Needed for pointer fields; filters with static storage do not need it. |

Schema choices matter as much as switches:

- `max_size` / `max_count` set the struct size, which is what a filter keeps
  on its stack (or in static storage). Keep them tight.
- Every field with rules costs a check on every packet; string format rules
  (`email`, `hostname`, `ip`) walk the string, the others are comparisons.
- Callback fields (no `max_size` / `max_count`) are not validated at all.

## Recommended for MCU filters

```
-DPB_BUFFER_ONLY -DPB_NO_ERRMSG
-DPB_VALIDATE_FILTER_STATIC_BUFFERS     # only if the filter is never re-entered
-DPB_VALIDATE_MAX_PATH_DEPTH=<your depth> -DPB_VALIDATE_MAX_PATH_LENGTH=<longest path + 1>
```

Keep `PB_VALIDATE_EARLY_EXIT` at 1 and `PB_VALIDATE_DEBUG` off. Call the
generated filters, or validators with a `NULL` buffer, on the hot path; pass
a `pb_violations_t` only where you report why a message was rejected.

## Measuring

    python validate/tests/c/validate_benchmark/bench.py [--iterations N] [--cc "arm-none-eabi-gcc ..."]

builds the benchmark in each configuration above and prints the tables in
markdown. Timings are the best of 7 runs; the peak stack is measured by
painting the stack before each call. The SConscript in the same directory
runs it with a few iterations as part of the test suite, checking that
valid packets pass and broken ones are rejected.
