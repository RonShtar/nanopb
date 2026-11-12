#!/usr/bin/env python3
# kate: replace-tabs on; indent-width 4;

"""
filters.py - the nanopb-validate protoc plugin: validators and packet filters
===================================================================================

This is a *separate* protoc plugin that layers our project-specific code on top
of stock nanopb output.  It exists so that `nanopb_generator.py` can stay
upstream nanopb: none of the logic here is patched into the upstream generator.

Responsibilities
----------------
1. Emit ``<base>_validate.h`` / ``<base>_validate.c``.  The actual validator
   code is produced by :mod:`validator` (with :mod:`rule_model`, :mod:`emitters`); this module only drives it.
2. Generate a *packet filter* -- a decode/identify/validate/reject boundary --
   for one nominated protocol entrypoint message, and inject it into the
   ``.pb.h`` and ``.pb.c`` that nanopb already generated, using protoc
   *insertion points* rather than by modifying the generator.

The filter as a security boundary
---------------------------------
The generated filter sits at the entrance of a communication path::

    untrusted bytes -> decode -> identify -> validate -> allow / reject

It is a security boundary, so the generator follows a strict policy:

  * unknown     -> reject at runtime
  * ambiguous   -> generation error
  * unsupported -> generation error
  * invalid     -> reject at runtime

Nothing about the protocol shape is guessed.  The user names the entrypoint
message; everything that is structurally present in the descriptors (that a
field is ``google.protobuf.Any``, that a oneof exists, its arms and their
types, the ``any.in`` allow-list) is derived from them; anything ambiguous is
a hard error rather than a pick.

Architecture
------------
The pipeline is layered so that no stage needs to understand the previous
one's inputs::

    CLI parameter        FilterOptions          (pure configuration)
          |
          v
    descriptors          DescriptorIndex        (FQN -> DescriptorProto; the
          |                                      semantic truth, unmangled)
          v
    analysis             ProtocolAnalyzer       (descriptors + nanopb IR)
          |
          v
    resolved model       FilterSpec             (fully resolved, C names baked in)
          |
          v
    emission             FilterEmitter          (FilterSpec -> C text; knows
                                                 nothing about the CLI)

The descriptors are the source of truth for protocol *semantics*; the nanopb IR
(:func:`nanopb_generator.parse_file`) is consulted only as a *C name oracle*, so
that the emitted code uses exactly the identifiers nanopb wrote into the .pb.h.

Generated API
-------------
For an entrypoint ``my_package.BaseMessage`` the filter is exposed as::

    int my_package_BaseMessage_filter_udp(void *ctx, const uint8_t *packet,
                                          size_t packet_size);
    int my_package_BaseMessage_filter_tcp(void *ctx, const uint8_t *packet,
                                          size_t packet_size, bool is_to_server);

Both are thin wrappers over one transport-independent static core, so the
filtering logic is not coupled to UDP or TCP.  Returns 0 to allow, -1 to reject.
Symbols are namespaced by the entrypoint message, so several filtered .proto
files can be linked into one binary.

How the injection works
-----------------------
nanopb emits ``/* @@protoc_insertion_point(...) */`` markers when it is run
with ``--protoc-insertion-points``.  A protoc plugin can then return a
``CodeGeneratorResponse.File`` whose ``name`` is an already-generated file and
whose ``insertion_point`` names one of those markers; protoc splices the
``content`` in at that spot.

Only three markers exist in nanopb, and ``struct:<Msg>`` sits *inside* the
struct body, so it is unusable for us.  That leaves:

    ===============  ===============  =========================================
    Target           Insertion point  What we inject
    ===============  ===============  =========================================
    ``<base>.pb.h``  ``eof``          filter declarations
    ``<base>.pb.c``  ``includes``     pb_decode.h / _validate.h
    ``<base>.pb.c``  ``eof``          filter core + transport wrappers
    ===============  ===============  =========================================

Ordering requirement
--------------------
protoc runs ``--*_out`` generators in command-line order, and a plugin may only
insert into a file produced *earlier in the same invocation*.  So nanopb must
run first, and with insertion points enabled::

    protoc \\
      --nanopb_out=--protoc-insertion-points,-x,validate.proto:. \\
      --nanopb-validate_out=--filter=pkg.BaseMessage,-x,validate.proto:. \\
      myfile.proto

Options that affect C naming (``-C``, ``--custom-style``, ``-s``, ``-f``,
``-I``, ``-x``) must be given to *both* plugins, because this plugin rebuilds
nanopb's intermediate representation via :func:`nanopb_generator.parse_file` in
order to see exactly the same mangled type names that nanopb emitted.

Scope of validation
-------------------
Validation covers statically allocated fields, including ``POINTER``
allocation.  ``pb_callback_t`` fields are deliberately *not* validated and no
decode-callback plumbing is generated for them.
"""

from __future__ import unicode_literals

import os
import sys


# nanopb's generator (read-only, from the checkout this tool lives in) does the
# descriptor parsing, option handling and naming styles; env.setup() puts it
# on sys.path and builds nanopb_pb2 and our validate_pb2.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import env  # noqa: E402
env.setup()

import nanopb_api as nanopb  # noqa: E402  (everything used from nanopb is listed there)
import validate_pb2  # noqa: E402
import c_layout  # noqa: E402
import rule_model  # noqa: E402
import validator  # noqa: E402

plugin_pb2 = nanopb.plugin_pb2
descriptor = nanopb.descriptor
from filter_model import (DescriptorIndex, GeneratorError, _dedupe, attach_validate_rules, ir_message_for_fqn,  # noqa: E402
                          strip_proto_ext)
from filter_options import (parse_plugin_parameter, split_own_options)  # noqa: E402
from filter_analyzer import (ProtocolAnalyzer)  # noqa: E402
from filter_emit import (FilterEmitter, ProtocolFilterEmitter, protocol_messages)  # noqa: E402


# ---------------------------------------------------------------------------
#                              Validator driver
# ---------------------------------------------------------------------------


def _message_validate_rules(msg):
    """Return the parsed (validate.message) MessageRules for a message, or None.

    Mirrors field_validate_rules() above, but reads the message-level
    extension (MessageOptions, field 1011) instead of the field-level one.
    """
    if validate_pb2 is None:
        return None
    try:
        opts = msg.desc.options
        if opts.HasExtension(validate_pb2.message):
            return opts.Extensions[validate_pb2.message]
    except (KeyError, AttributeError):
        pass
    return None


def build_validator_generator(f, force_names=()):
    """Create and populate a ValidatorGenerator for one ProtoFile.

    Args:
        f: the nanopb ProtoFile.
        force_names: fully qualified names of messages that must get a validator
            even when they declare no rules.  The filter calls these directly,
            so the symbol has to exist.
    """
    validator_gen = validator.ValidatorGenerator(f)

    # Add validators for all messages that carry rules, field-level or
    # message-level ((validate.message).requires/mutex/at_least).
    for msg in f.messages:
        if hasattr(msg, 'fields'):
            validator_gen.add_message_validator(msg, _message_validate_rules(msg))

    # Always emit validation functions, even when no message declares a rule,
    # so that a filter has something to call for every message on its path.
    if not validator_gen.validators:
        for msg in f.messages:
            if hasattr(msg, 'fields'):
                validator_gen.force_add_message_validator(msg, _message_validate_rules(msg))

    for fqn in force_names:
        msg = ir_message_for_fqn(f, fqn)
        # Only messages of this file: another file's message gets its
        # validator from that file, and a second copy here would be a
        # duplicate definition.
        if msg is not None and getattr(msg, 'protofile', f) is f and \
                str(msg.name) not in validator_gen.validators:
            validator_gen.force_add_message_validator(msg, _message_validate_rules(msg))

    # Messages of other files: their file emits a validator only under the
    # same rules, so ask (and cache) instead of assuming one exists.
    def external_has_validator(ctype):
        dep = getattr(f, 'dependencies', {}).get(str(ctype))
        if dep is None or not hasattr(dep, 'protofile') or dep.protofile is f:
            return True
        return _validator_index(dep.protofile, dep)

    validator_gen.external_has_validator = external_has_validator

    # A message without rules of its own still needs a validator when one of
    # its sub-messages has one; otherwise those rules are never reached (and
    # parents would call a function that does not exist).
    changed = True
    while changed:
        changed = False
        for msg in f.messages:
            if not hasattr(msg, 'fields') or str(msg.name) in validator_gen.validators:
                continue
            desc = getattr(msg, 'desc', None)
            if desc is not None and desc.options.map_entry:
                continue  # map values are validated in place by the parent
            for field in msg.fields:
                ctype = getattr(field, 'ctype', None)
                if getattr(field, 'pbtype', None) not in ('MESSAGE', 'MSG_W_CB') or not ctype:
                    continue
                lowered = str(ctype).lower()
                if 'google' in lowered and 'protobuf' in lowered:
                    continue
                if validator_gen._has_validator(ctype):
                    validator_gen.force_add_message_validator(msg, _message_validate_rules(msg))
                    changed = True
                    break

    return validator_gen


class ValidatorIndex(object):
    """Answers "will file F emit a pb_validate_* for message M?".

    Used to decide whether a cross-file payload can be validated, or declares no
    rules at all.  Results are cached because the answer costs a full parse of
    the dependency's rules.
    """

    def __init__(self):
        self._cache = {}

    def __call__(self, protofile, ir_msg):
        key = protofile.fdesc.name
        if key not in self._cache:
            self._cache[key] = set(build_validator_generator(protofile).validators.keys())
        return str(ir_msg.name) in self._cache[key]


_validator_index = ValidatorIndex()


def process_file(filename, fdesc, options, filter_options, index,
                 other_files, validator_index, generated_entries=None):
    """Produce every output this plugin owns, for one .proto file.

    Returns a list of (name, insertion_point_or_None, content) tuples ready to
    be turned into CodeGeneratorResponse entries.  The requested entrypoints
    whose filter this file hosts are added to ``generated_entries``.
    """
    f = nanopb.parse_file(filename, fdesc, options)
    attach_validate_rules(f)

    # Check the list of dependencies, and if they are available in other_files,
    # add them to be considered for import resolving. Recursively add any files
    # imported by the dependencies.  This mirrors nanopb_generator.process_file,
    # and both the validator and the filter need it: the validator to emit
    # `#include "<dep>_validate.h"` for cross-file field types, the filter to
    # resolve payload messages defined in another .proto.
    deps = list(f.fdesc.dependency)
    while deps:
        dep = deps.pop(0)
        if dep in other_files:
            f.add_dependency(other_files[dep])
            deps += list(other_files[dep].fdesc.dependency)

    # Resolve each filter once, up front. Every later stage reads this one model
    # rather than re-deriving protocol facts, so the header and the source can
    # never disagree about what the filter does.
    specs = []
    for name in filter_options.filter_messages:
        spec = ProtocolAnalyzer(f, index, filter_options.for_entry(name),
                                validator_index).analyze()
        if spec is not None:
            specs.append(spec)
            if generated_entries is not None:
                generated_entries.add(name)

    # Match nanopb's own output naming exactly, so our insertion targets line up.
    noext = os.path.splitext(filename)[0]
    headername = noext + options.extension + options.header_extension
    sourcename = noext + options.extension + options.source_extension

    outputs = []

    # 1. The standalone validator files.  Messages on the filter path get a
    #    validator even if they declare no rules, so the filter's direct calls
    #    always resolve.
    # Filters call the validators of the messages they decode directly, so
    # those must exist even when a message declares no rules.
    local = set(entry.fqn for entry in index.by_fqn.values() if entry.filename == filename)
    force = _dedupe([name for spec in specs for name in spec.required_validators()] +
                    [fqn for fqn in filter_options.protocol_messages if fqn in local])
    validator_gen = build_validator_generator(f, force)
    validate_headerdata = ''.join(validator_gen.generate_header())
    validate_sourcedata = ''.join(validator_gen.generate_source())
    if validate_headerdata or validate_sourcedata:
        outputs.append((noext + '_validate' + options.header_extension,
                        None, validate_headerdata))
        outputs.append((noext + '_validate' + options.source_extension,
                        None, validate_sourcedata))

    # 2. The filters, spliced into the files nanopb already produced. protoc
    #    appends repeated insertions at one point in order, and every symbol is
    #    namespaced by its entrypoint, so several filters share a file safely.
    if filter_options.filter_name and not filter_options.protocol_filter:
        for spec in specs:
            spec.public_name = filter_options.filter_name
    for spec in specs:
        emitter = FilterEmitter(spec)
        outputs.append((headername, 'eof', ''.join(emitter.header_lines())))
        outputs.append((sourcename, 'includes', ''.join(emitter.include_lines(f, options))))
        outputs.append((sourcename, 'eof', ''.join(emitter.source_lines())))

    return outputs


def main_plugin():
    """Main function when invoked as a protoc plugin."""
    import io

    if sys.platform == "win32":
        import msvcrt
        # Set stdin and stdout to binary mode
        msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)
        msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)

    data = io.open(sys.stdin.fileno(), "rb").read()
    request = plugin_pb2.CodeGeneratorRequest.FromString(data)
    response = plugin_pb2.CodeGeneratorResponse()

    try:
        args = parse_plugin_parameter(request.parameter)
        filter_options, nanopb_args = split_own_options(args)

        nanopb.optparser.usage = ("protoc --nanopb-validate_out=outdir "
                                  "[--nanopb-validate_opt=option] file.proto")
        options, _ = nanopb.process_cmdline(nanopb_args, is_plugin=True)
        # Our headers (pb_validate.h, pb_decode.h, pb.h) use nanopb's -L format too.
        c_layout.LIBRARY_INCLUDE_FORMAT = options.libformat

        # Google's protoc does not currently indicate the full path of proto
        # files.  Instead always add the main file path to the search dirs,
        # that works for the common case.
        options.options_path.append(os.path.dirname(request.file_to_generate[0]))

        # The pristine descriptors are the source of truth for protocol shape.
        index = DescriptorIndex(request.proto_file)

        # Process any include files first, in order to have them available as
        # dependencies when resolving cross-file message references.
        other_files = {}
        for fdesc in request.proto_file:
            dep = nanopb.parse_file(fdesc.name, fdesc, options)
            attach_validate_rules(dep)
            other_files[fdesc.name] = dep

        validator_index = ValidatorIndex()
        generated_entries = set()
        if filter_options.protocol_filter:
            filter_options.protocol_messages = protocol_messages(index, set(request.file_to_generate))
        validate_headers = []

        for filename in request.file_to_generate:
            for fdesc in request.proto_file:
                if fdesc.name == filename:
                    for name, insertion_point, content in process_file(
                            filename, fdesc, options, filter_options, index,
                            other_files, validator_index, generated_entries):
                        entry = response.file.add()
                        entry.name = name
                        if insertion_point:
                            entry.insertion_point = insertion_point
                        entry.content = c_layout.tidy_c(content)
                        if not insertion_point and name.endswith('_validate' + options.header_extension):
                            validate_headers.append(name)

        if filter_options.protocol_filter:
            # One file that resolves every message of the request by name.
            hub = other_files[request.file_to_generate[0]]
            for other in other_files.values():
                if other is not hub:
                    hub.add_dependency(other)
            pb_headers = [strip_proto_ext(n) + options.extension + options.header_extension
                          for n in request.file_to_generate]
            emitter = ProtocolFilterEmitter(filter_options.protocol_filter, hub, index,
                                            filter_options.protocol_messages, pb_headers, validate_headers,
                                            filter_options.filter_name)
            for suffix, content in ((options.header_extension, emitter.header()),
                                    (options.source_extension, emitter.source())):
                entry = response.file.add()
                entry.name = filter_options.protocol_filter + '_filter' + suffix
                entry.content = c_layout.tidy_c(''.join(content))

        missing = [m for m in filter_options.filter_messages if m not in generated_entries]
        if missing:
            # The entrypoint resolved (the analyzer would have raised otherwise)
            # but lives in a file this invocation was not asked to generate, so
            # nobody emitted a filter. Silently producing none would leave the
            # boundary missing at link time.
            raise GeneratorError(
                "--filter=%s names a message defined in a file that is not being "
                "generated in this invocation (%s). Run the plugin on the .proto "
                "that defines the entrypoint."
                % (';'.join(missing), ', '.join(request.file_to_generate)))

    except GeneratorError as e:
        # Reported by protoc as a plugin failure, without a Python traceback.
        response.ClearField('file')
        response.error = str(e)
    except rule_model.ValidationRuleNotImplementedError as e:
        # A declared validate.proto option has no C-runtime enforcement yet
        # (see emitters.RuleEmitterRegistry.emit and the guard checks
        # in FieldValidator._parse_string_rules/_parse_bytes_rules). Surfaced
        # the same way as GeneratorError: a clean protoc failure, not a
        # traceback, so it reads like any other "fix your .proto" error.
        response.ClearField('file')
        response.error = str(e)

    if hasattr(plugin_pb2.CodeGeneratorResponse, "FEATURE_PROTO3_OPTIONAL"):
        response.supported_features = plugin_pb2.CodeGeneratorResponse.FEATURE_PROTO3_OPTIONAL

    if hasattr(plugin_pb2.CodeGeneratorResponse, "FEATURE_SUPPORTS_EDITIONS"):
        response.supported_features |= plugin_pb2.CodeGeneratorResponse.FEATURE_SUPPORTS_EDITIONS
        response.minimum_edition = descriptor.EDITION_PROTO2
        response.maximum_edition = descriptor.EDITION_2024

    io.open(sys.stdout.fileno(), "wb").write(response.SerializeToString())


if __name__ == '__main__':
    main_plugin()
