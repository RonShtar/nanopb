# Architecture

## Core mental model

Treat `<repo_root>` as the root of this checkout.

Nanopb is split into a tiny portable C runtime and a Python generator that turns protobuf schemas into C structs plus descriptor tables. Most tasks fall on one side of that boundary:

- Runtime-side work changes encoding, decoding, descriptors, stream handling, or validation behavior in `<repo_root>/pb*.c` and `<repo_root>/pb*.h`
- Generator-side work changes how `.proto` input becomes generated `.pb.h`, `.pb.c`, and optional `*_validate.*` files under `<repo_root>/generator/`

## Runtime pieces

- `<repo_root>/pb.h` defines compile-time feature switches and shared types. Start here when behavior depends on macros such as malloc support, 32-bit field sizes, packed structs, or UTF-8 validation.
- `<repo_root>/pb_common.c` contains descriptor and shared support code used by both encode and decode paths.
- `<repo_root>/pb_encode.c` implements stream-oriented protobuf encoding.
- `<repo_root>/pb_decode.c` implements stream-oriented protobuf decoding.
- `<repo_root>/validate/runtime/pb_validate.c` adds optional generated-message validation support.

The runtime intentionally uses stream abstractions instead of depending only on memory buffers. That keeps it suitable for embedded transport and file/network use without requiring large temporary allocations.

## Generator pieces

- `<repo_root>/generator/nanopb_generator.py` is the main entrypoint and owns parsing, IR construction, naming, and C emission.
- `<repo_root>/validate/nanopb_validate/` (`rule_model.py`, `emitters.py`, `validator.py`) is a dependency-free library that parses `(validate.*)` options into an IR and emits the C body of `pb_validate_<Message>()` functions from it; it has no protoc plugin entrypoint of its own.
- `<repo_root>/validate/nanopb_validate/filters.py` is the actual `protoc-gen-nanopb-validate` plugin entrypoint. It drives `nanopb_validator.py` to emit `*_validate.h`/`*_validate.c`, and separately owns the packet-filter feature (`pkg_Msg_filter_udp`/`filter_tcp`, spliced into nanopb's own `.pb.h`/`.pb.c` via `--protoc-insertion-points`).
- `<repo_root>/generator/proto/` contains generator-owned schema files used by the plugin itself.
- `<repo_root>/generator/protoc-gen-nanopb` and related wrappers expose the generator as a `protoc` plugin.

The generator is the architectural center for schema semantics: if generated code shape looks wrong, the fix is usually here rather than in handwritten runtime code.

## Validation path

Validation is a full cross-cutting feature:

- Schema options live in `<repo_root>/validate/nanopb_validate/validate_proto/validate.proto`
- Rule parsing and C emission live in `<repo_root>/validate/nanopb_validate/validator.py`
- The protoc plugin driving it (and the packet-filter feature) lives in `<repo_root>/validate/nanopb_validate/filters.py`
- Runtime support lives in `<repo_root>/validate/runtime/pb_validate.c` and `pb_validate.h`
- End-to-end tests live in `<repo_root>/validate/tests/c/validation/` (and the other `validate/tests/c/` folders)

If you change any one of those layers, verify the others still agree.

A `.proto` option with no C-runtime enforcement (e.g. `string.pattern`, which
would need a regex engine) is a generation-time error, not a silently-ignored
no-op: `rule_model.ValidationRuleNotImplementedError`, raised either
while parsing an unsupported option or from `RuleEmitterRegistry.emit()`'s
fallback when no emitter is registered for a rule type, is caught in
`filters.main_plugin()` and reported as a normal protoc
plugin failure.

The runtime distinguishes two build modes via a single compile-time macro,
`PB_VALIDATE_DEBUG` (undefined by default): without it, `pb_validate_*`
functions honor `PB_VALIDATE_EARLY_EXIT` (default on) and every macro's
"record a violation" step is a lightweight, allocation-free struct write; with
it defined, validation always collects every violation on a message (ignoring
`PB_VALIDATE_EARLY_EXIT`) and numeric/string-length violations carry the
actual/expected values in their message text. Generated `*_validate.c` files
are identical in both modes -- the macros in `pb_validate.h` are what change,
not the generated call sites -- so there is no separate generator flag for it.

## Design choices that show up in reviews

- Generated descriptors replace runtime reflection to minimize code size and RAM use.
- The runtime can be built as encode-only or decode-only, so avoid unnecessary coupling between those paths.
- Compatibility is validated across many build systems; changes to packaging or integration files are treated as product code, not as secondary tooling.
- Tests act as executable specification. Look for an existing test directory before deciding behavior is undefined.
