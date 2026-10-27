---
name: nanopb-codegen
description: Create or modify .proto schemas and their nanopb .options for embedded C, then generate .pb.c/.pb.h and verify they are fully statically sized. Use when adding or changing protobuf messages, or to smoke-test generator changes against a schema.
---

# nanopb code generation

1. **Schema** — edit or create `proto/<name>.proto` (create `proto/` if missing). Never renumber existing tags or change a field's wire type; add new fields with fresh tags.
2. **Static bounds** — in `proto/<name>.options`, give every `string`/`bytes` field a `max_size` and every `repeated` field a `max_count`:
   ```
   Telemetry.device_name      max_size:32
   Telemetry.sensor_readings  max_count:16
   ```
   Only leave a field unbounded (callback) if the user explicitly asked for it.
3. **Generate** (from repo root; the PostToolUse hook also does this on edits under `proto/`):
   `python generator/nanopb_generator.py -I proto -D generated proto/*.proto`
4. **Verify**
   - `generated/<name>.pb.h` has no `pb_callback_t` members (`grep -n pb_callback_t generated/*.pb.h` must print nothing).
   - Each message has a `<Msg>_size` define; if it's missing, a field is still unbounded.
   - Show the user the generated struct(s) and `_size` values.
5. **Usage code** — init with `<Msg>_init_zero`, size buffers with `<Msg>_size`, no heap allocation, and check `pb_encode`/`pb_decode` return values (`PB_GET_ERROR(&stream)`).
6. If no C compiler is available (the current state of this machine), say the generated code was not compiled.

When testing a generator change rather than a schema, run step 3 on the closest existing case in `tests/` with output to a scratch dir outside the repo, and diff against the output from before the change.
