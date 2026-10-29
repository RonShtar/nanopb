#!/usr/bin/env python3
# kate: replace-tabs on; indent-width 4;

"""
nanopb_validate_generator.py - project-specific validation and packet-filter codegen
===================================================================================

This is a *separate* protoc plugin that layers our project-specific code on top
of stock nanopb output.  It exists so that `nanopb_generator.py` can stay
upstream nanopb: none of the logic here is patched into the upstream generator.

Responsibilities
----------------
1. Emit ``<base>_validate.h`` / ``<base>_validate.c``.  The actual validator
   code is produced by :mod:`nanopb_validator`; this module only drives it.
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
import shlex
import sys

from collections import OrderedDict

# The heavy lifting - descriptor parsing, option handling, naming styles - is
# all reused from nanopb_generator.  Importing it also builds nanopb_pb2 and
# validate_pb2 as a side effect, which is what makes nanopb_validator usable.
if not __package__:
    import nanopb_generator as nanopb
else:
    from . import nanopb_generator as nanopb

Globals = nanopb.Globals
OneOf = nanopb.OneOf
plugin_pb2 = nanopb.plugin_pb2
descriptor = nanopb.descriptor

# validate.proto and the validator itself are ours, not nanopb's, so we import
# them here rather than leaning on nanopb_generator to have done it.  Importing
# nanopb_generator above already built the generated _pb2 modules.
try:
    from proto import validate_pb2  # Generated from validate.proto
except ImportError:
    try:
        import validate_pb2  # fallback if PYTHONPATH already contains it
    except ImportError:
        validate_pb2 = None

try:
    from proto import nanopb_validator
except ImportError:
    try:
        import nanopb_validator
    except ImportError:
        nanopb_validator = None


class GeneratorError(Exception):
    """Raised for user-facing errors that should surface as a protoc failure."""


# Fully qualified name of the well-known Any type, as it appears in
# FieldDescriptorProto.type_name (which is always leading-dot qualified).
ANY_TYPE_NAME = '.google.protobuf.Any'

# Default host portion of a type_url, as used by the protobuf runtimes.
DEFAULT_TYPE_URL_HOST = 'type.googleapis.com'

# Filter return codes.  0 allows the packet through, -1 rejects it.
RET_ALLOW = '0'
RET_REJECT = '-1'


# ---------------------------------------------------------------------------
#                        Validation rule IR enrichment
# ---------------------------------------------------------------------------


def attach_validate_rules(f):
    """Attach `validate_rules` to every field of every message in a ProtoFile.

    nanopb's IR knows nothing about validate.proto, so after
    :func:`nanopb_generator.parse_file` has built the IR we walk it once and
    hang the parsed ``(validate.rules)`` extension off each Field.  That is the
    only thing :mod:`nanopb_validator` needs from us.

    Fields are matched to their descriptors by field *number* rather than by
    position, because nanopb folds oneof members into a single OneOf entry and
    reorders `msg.fields` relative to `msg.desc.field`.
    """
    for msg in f.messages:
        rules_by_number = {}
        if validate_pb2 is not None:
            for fdesc in getattr(msg.desc, 'field', []):
                try:
                    if fdesc.options.HasExtension(validate_pb2.rules):
                        rules_by_number[fdesc.number] = fdesc.options.Extensions[validate_pb2.rules]
                except (KeyError, AttributeError):
                    # Extension not available or not properly registered
                    pass

        for field in msg.fields:
            # OneOf is a container; the rules belong on its members.
            members = field.fields if isinstance(field, OneOf) else [field]
            for member in members:
                member.validate_rules = rules_by_number.get(
                    getattr(member, 'tag', None), None)


def field_validate_rules(field_desc):
    """Return the parsed ``(validate.rules)`` for a FieldDescriptorProto, or None."""
    if validate_pb2 is None:
        return None
    try:
        if field_desc.options.HasExtension(validate_pb2.rules):
            return field_desc.options.Extensions[validate_pb2.rules]
    except (KeyError, AttributeError):
        pass
    return None


# ---------------------------------------------------------------------------
#                    Descriptor layer: the semantic truth
# ---------------------------------------------------------------------------
#
# Everything about *what the protocol is* is decided here, against the pristine
# FileDescriptorProtos that protoc handed us.  The nanopb IR is deliberately not
# consulted at this layer: its type names are mangled by -C / mangle_names /
# --custom-style, and its `msg.desc` copies have had field type_names rewritten.


class DescriptorEntry(object):
    """One message, identified by its protobuf fully qualified name."""

    __slots__ = ('fqn', 'filename', 'desc')

    def __init__(self, fqn, filename, desc):
        self.fqn = fqn
        self.filename = filename
        self.desc = desc

    def __repr__(self):
        return 'DescriptorEntry(%r, %r)' % (self.fqn, self.filename)


class DescriptorIndex(object):
    """Fully qualified name -> :class:`DescriptorEntry` for the whole request.

    Built once per protoc invocation from ``request.proto_file``, which contains
    every file the compilation transitively depends on.  Lookups are exact: a
    security filter must never resolve a name by fuzzy matching.
    """

    def __init__(self, fdescs):
        self.by_fqn = OrderedDict()
        for fdesc in fdescs:
            for fqn, desc in self._walk(fdesc):
                # First definition wins; duplicate FQNs across files are a
                # protoc-level error we will never see here.
                self.by_fqn.setdefault(fqn, DescriptorEntry(fqn, fdesc.name, desc))

    @staticmethod
    def _walk(fdesc):
        """Yield (fqn, DescriptorProto) for every message, nested ones included."""
        def rec(prefix, messages):
            for msg in messages:
                fqn = prefix + '.' + msg.name if prefix else msg.name
                yield fqn, msg
                for item in rec(fqn, msg.nested_type):
                    yield item

        for item in rec(fdesc.package, fdesc.message_type):
            yield item

    def lookup(self, name):
        """Resolve a fully qualified message name.  Returns None if unknown."""
        if not name:
            return None
        return self.by_fqn.get(name.lstrip('.'))

    def candidates(self, filename=None):
        """Sorted FQNs, optionally restricted to one file.  Used in error text."""
        return sorted(entry.fqn for entry in self.by_fqn.values()
                      if filename is None or entry.filename == filename)


def real_oneof_indices(desc):
    """Indices of the *user-written* oneofs in a DescriptorProto.

    proto3 ``optional`` fields are represented as single-member synthetic
    oneofs.  They carry no dispatch meaning and must not be mistaken for a
    payload union.
    """
    synthetic = set()
    for field in desc.field:
        if field.HasField('oneof_index') and getattr(field, 'proto3_optional', False):
            synthetic.add(field.oneof_index)
    return [i for i in range(len(desc.oneof_decl)) if i not in synthetic]


def oneof_members(desc, index):
    """FieldDescriptorProtos belonging to oneof `index`, in declaration order."""
    return [field for field in desc.field
            if field.HasField('oneof_index') and field.oneof_index == index]


def any_payload_fields(desc):
    """Singular fields of type ``google.protobuf.Any``.

    The check is an exact match on the descriptor's ``type_name``; substring
    matching on mangled C names would accept unrelated types such as
    ``google.protobuf.AnyValue`` or a user type in a package named ``google``.
    """
    fields = []
    for field in desc.field:
        if field.type_name == ANY_TYPE_NAME:
            fields.append(field)
    return fields


# ---------------------------------------------------------------------------
#                     Resolved filter model (the IR)
# ---------------------------------------------------------------------------
#
# Everything below this point works off a FilterSpec alone.  The emitter never
# sees the CLI, the descriptors, or the nanopb IR: every C identifier it needs
# has already been resolved and baked in.


class Strategy(object):
    """How the filter identifies the message carried by a packet."""

    SINGLE = 'single'   # every packet is the entrypoint message, full stop
    ONEOF = 'oneof'     # entrypoint carries a oneof payload; dispatch on the tag
    ANY = 'any'         # entrypoint carries a google.protobuf.Any; dispatch on type_url

    ALL = (SINGLE, ONEOF, ANY)


class MessageRef(object):
    """A message resolved all the way down to the C identifiers nanopb emitted."""

    __slots__ = ('fqn', 'ctype', 'init_zero', 'msgdesc', 'validator_func',
                 'validate_header')

    def __init__(self, fqn, ctype, init_zero, msgdesc, validator_func, validate_header):
        self.fqn = fqn
        self.ctype = ctype                    # e.g. "my_package_BaseMessage"
        self.init_zero = init_zero            # e.g. "my_package_BaseMessage_init_zero"
        self.msgdesc = msgdesc                # e.g. "my_package_BaseMessage_msg"
        self.validator_func = validator_func  # pb_validate_* name, or None if no rules
        self.validate_header = validate_header  # "<base>_validate.h" if cross-file

    def __repr__(self):
        return 'MessageRef(%r)' % (self.fqn,)


class Route(object):
    """One arm of the filter's dispatch table."""

    __slots__ = ('kind', 'case_label', 'comment', 'target', 'access', 'type_url')

    #: payload is a submessage reached through the oneof union
    ONEOF_MESSAGE = 'oneof-message'
    #: payload is a scalar oneof arm; it has no descriptor of its own and is
    #: already covered by validating the entrypoint message
    ONEOF_SCALAR = 'oneof-scalar'
    #: payload is a serialized message inside a google.protobuf.Any
    ANY_PAYLOAD = 'any-payload'

    def __init__(self, kind, case_label, comment, target=None, access=None, type_url=None):
        self.kind = kind
        self.case_label = case_label
        self.comment = comment
        self.target = target
        self.access = access
        self.type_url = type_url


class FilterSpec(object):
    """A fully resolved filter, ready to emit.

    Attributes:
        entry: :class:`MessageRef` for the protocol entrypoint.
        strategy: one of :class:`Strategy`.
        symbol_prefix: C symbol prefix for the generated functions.
        dispatch_expr: C expression the dispatch switches on, or None for SINGLE.
        presence_expr: C expression guarding payload presence, or None.
        routes: tuple of :class:`Route`.
        extra_headers: extra ``*_validate.h`` includes the filter body needs.
    """

    __slots__ = ('entry', 'strategy', 'symbol_prefix', 'dispatch_expr',
                 'presence_expr', 'routes', 'extra_headers')

    def __init__(self, entry, strategy, symbol_prefix, dispatch_expr=None,
                 presence_expr=None, routes=(), extra_headers=()):
        self.entry = entry
        self.strategy = strategy
        self.symbol_prefix = symbol_prefix
        self.dispatch_expr = dispatch_expr
        self.presence_expr = presence_expr
        self.routes = tuple(routes)
        self.extra_headers = tuple(extra_headers)

    @property
    def udp_signature(self):
        return ('int %s_filter_udp(void *ctx, const uint8_t *packet, size_t packet_size)'
                % self.symbol_prefix)

    @property
    def tcp_signature(self):
        return ('int %s_filter_tcp(void *ctx, const uint8_t *packet, size_t packet_size, '
                'bool is_to_server)' % self.symbol_prefix)

    @property
    def core_signature(self):
        return ('static int %s_filter_core(const uint8_t *packet, size_t packet_size)'
                % self.symbol_prefix)

    #: Messages whose validators must exist because the filter calls them.
    def required_validators(self):
        names = [self.entry.fqn]
        for route in self.routes:
            if route.target is not None:
                names.append(route.target.fqn)
        return names


# ---------------------------------------------------------------------------
#                          C naming (the name oracle)
# ---------------------------------------------------------------------------
#
# The one place that is allowed to translate protobuf names into C identifiers.
# It goes through the nanopb IR so that the result is byte-for-byte what nanopb
# wrote into the .pb.h, under whatever naming style and mangling is in effect.


def ir_message_for_fqn(f, fqn):
    """Find the nanopb IR Message for a fully qualified protobuf name.

    ``ProtoFile.add_dependency`` keys ``f.dependencies`` by the *canonical*
    unmangled underscore form of each message name -- exactly ``fqn`` with dots
    replaced by underscores -- for this file and every dependency added to it.
    Reusing that index means mangling options are handled for free.
    """
    return f.dependencies.get(fqn.replace('.', '_'))


def validator_func_name(ir_msg):
    """Name of the ``pb_validate_*`` function nanopb_validator emits for a message."""
    return 'pb_validate_' + str(ir_msg.name).replace('.', '_')


def validate_header_for(ir_msg):
    """``<base>_validate.h`` for the file that defines `ir_msg`, or None."""
    protofile = getattr(ir_msg, 'protofile', None)
    if protofile is None:
        return None
    base = protofile.fdesc.name
    if base.endswith('.proto'):
        base = base[:-6]
    return base + '_validate.h'


def strip_proto_ext(filename):
    return filename[:-6] if filename.endswith('.proto') else filename


def type_url_hash(text):
    """The rolling hash the generated C computes over a type_url.

    Kept in lockstep with the loop emitted by :meth:`FilterEmitter._any_dispatch`.
    """
    value = 0
    for char in text:
        value = (value * 31 + ord(char)) & 0xFFFFFFFF
    return value


# ---------------------------------------------------------------------------
#                            Protocol analysis
# ---------------------------------------------------------------------------


class ProtocolAnalyzer(object):
    """Turn (CLI options + descriptors + nanopb IR) into a :class:`FilterSpec`.

    This is the only stage that makes decisions about protocol shape, and it
    makes them exhaustively: every case it does not fully understand raises
    :class:`GeneratorError` instead of choosing.
    """

    def __init__(self, protofile, index, filter_options, validator_lookup):
        self.f = protofile
        self.index = index
        self.opts = filter_options
        # callable(ProtoFile, ir_msg) -> bool: will a pb_validate_* be emitted?
        self.validator_lookup = validator_lookup

    # -- entry points -------------------------------------------------------

    def analyze(self):
        """Return a FilterSpec, or None if this file hosts no filter.

        None means "the requested entrypoint lives in another file of this
        compilation", which is normal when one set of options is applied to
        several .proto files.  A genuinely unresolvable entrypoint is an error.
        """
        if not self.opts.filter_message:
            return None

        entry_desc = self.index.lookup(self.opts.filter_message)
        if entry_desc is None:
            # List this file's own messages: the well-known types that also sit
            # in the index are never what the user meant, and burying the real
            # candidates under them makes the error useless.
            local = self.index.candidates(self.f.fdesc.name)
            raise GeneratorError(
                "--filter=%s does not name any message in the compiled "
                "descriptors.\nUse a fully qualified name. Messages defined in "
                "%s:\n%s"
                % (self.opts.filter_message, self.f.fdesc.name,
                   '\n'.join('  - ' + name for name in local) or '  (none)'))

        if entry_desc.filename != self.f.fdesc.name:
            # The filter belongs to whichever file defines the entrypoint.
            return None

        entry_ir = ir_message_for_fqn(self.f, entry_desc.fqn)
        if entry_ir is None:
            raise GeneratorError(
                "--filter=%s resolved to a message that nanopb did not generate "
                "a struct for (it may be excluded by skip_message or "
                "discard_deprecated). No filter can be generated for it."
                % entry_desc.fqn)

        strategy = self._select_strategy(entry_desc)
        entry_ref = self._message_ref(entry_desc.fqn, entry_ir)
        symbol_prefix = Globals.naming_style.func_name(entry_ir.name)

        if strategy == Strategy.SINGLE:
            return FilterSpec(entry_ref, strategy, symbol_prefix)
        if strategy == Strategy.ONEOF:
            return self._build_oneof_spec(entry_desc, entry_ir, entry_ref, symbol_prefix)
        return self._build_any_spec(entry_desc, entry_ir, entry_ref, symbol_prefix)

    # -- strategy selection -------------------------------------------------

    def _select_strategy(self, entry_desc):
        """Decide how packets are identified, or refuse to.

        `--filter-mode` defaults to `auto`, which derives the shape from the
        descriptors.  Anything the schema leaves ambiguous is an error: the user
        resolves it by asserting a mode explicitly, which is then checked
        against the schema rather than trusted.
        """
        desc = entry_desc.desc
        any_fields = any_payload_fields(desc)
        oneofs = real_oneof_indices(desc)
        requested = self.opts.filter_mode

        if requested == Strategy.SINGLE:
            return Strategy.SINGLE

        if requested == Strategy.ANY:
            if not any_fields:
                raise GeneratorError(
                    "--filter-mode=any, but '%s' has no google.protobuf.Any field."
                    % entry_desc.fqn)
            if len(any_fields) > 1:
                raise GeneratorError(self._multi_any_message(entry_desc, any_fields))
            self._reject_repeated(entry_desc, any_fields[0])
            return Strategy.ANY

        if requested == Strategy.ONEOF:
            if not oneofs:
                raise GeneratorError(
                    "--filter-mode=oneof, but '%s' declares no oneof."
                    % entry_desc.fqn)
            if len(oneofs) > 1:
                raise GeneratorError(self._multi_oneof_message(entry_desc, oneofs))
            return Strategy.ONEOF

        # requested == 'auto': derive, but never guess.
        if len(any_fields) > 1:
            raise GeneratorError(self._multi_any_message(entry_desc, any_fields))
        if len(oneofs) > 1:
            raise GeneratorError(self._multi_oneof_message(entry_desc, oneofs))
        if any_fields and oneofs:
            raise GeneratorError(
                "'%s' carries both a google.protobuf.Any field ('%s') and a oneof "
                "('%s'), so the payload it dispatches on is ambiguous.\n"
                "Pick one explicitly with --filter-mode=any, --filter-mode=oneof "
                "or --filter-mode=single."
                % (entry_desc.fqn, any_fields[0].name,
                   desc.oneof_decl[oneofs[0]].name))
        if any_fields:
            self._reject_repeated(entry_desc, any_fields[0])
            return Strategy.ANY
        if oneofs:
            return Strategy.ONEOF
        return Strategy.SINGLE

    def _reject_repeated(self, entry_desc, field_desc):
        label_repeated = nanopb.descriptor.FieldDescriptorProto.LABEL_REPEATED
        if field_desc.label == label_repeated:
            raise GeneratorError(
                "'%s.%s' is a repeated google.protobuf.Any. A filter cannot "
                "dispatch on a repeated payload; wrap it in a singular field or "
                "use --filter-mode=single."
                % (entry_desc.fqn, field_desc.name))

    def _multi_any_message(self, entry_desc, any_fields):
        return (
            "'%s' has %d google.protobuf.Any fields (%s), so the payload the "
            "filter should dispatch on is ambiguous.\nA filter entrypoint must "
            "carry exactly one Any field, or use --filter-mode=single to decode "
            "and validate the entrypoint only."
            % (entry_desc.fqn, len(any_fields),
               ', '.join(field.name for field in any_fields)))

    def _multi_oneof_message(self, entry_desc, oneofs):
        names = [entry_desc.desc.oneof_decl[i].name for i in oneofs]
        return (
            "'%s' declares %d oneofs (%s), so the payload the filter should "
            "dispatch on is ambiguous.\nA filter entrypoint must declare exactly "
            "one oneof, or use --filter-mode=single to decode and validate the "
            "entrypoint only."
            % (entry_desc.fqn, len(oneofs), ', '.join(names)))

    # -- oneof strategy -----------------------------------------------------

    def _build_oneof_spec(self, entry_desc, entry_ir, entry_ref, symbol_prefix):
        index = real_oneof_indices(entry_desc.desc)[0]
        oneof_name = entry_desc.desc.oneof_decl[index].name

        oneof_ir = None
        for field in entry_ir.fields:
            if isinstance(field, OneOf) and field.name == oneof_name:
                oneof_ir = field
                break
        if oneof_ir is None:
            raise GeneratorError(
                "nanopb did not generate a union for oneof '%s' in '%s'; it may "
                "have been split by field options. A filter cannot dispatch on it."
                % (oneof_name, entry_desc.fqn))

        oneof_var = Globals.naming_style.var_name(oneof_ir.name)
        # An anonymous union lifts its members straight into the struct.
        prefix = 'envelope.' if oneof_ir.anonymous else 'envelope.%s.' % oneof_var

        members_ir = {field.name: field for field in oneof_ir.fields}
        routes = []
        extra_headers = []

        for member_desc in oneof_members(entry_desc.desc, index):
            member_ir = members_ir.get(member_desc.name)
            if member_ir is None:
                # nanopb dropped the arm (skipped/ignored field). Leaving it out
                # of the switch would silently make it unroutable, so refuse.
                raise GeneratorError(
                    "oneof arm '%s.%s.%s' has no nanopb field, so the filter "
                    "cannot route it. Remove the field option that drops it, or "
                    "use --filter-mode=single."
                    % (entry_desc.fqn, oneof_name, member_desc.name))

            case_label = Globals.naming_style.define_name(
                '%s_%s_tag' % (entry_ir.name, member_ir.name))

            if member_ir.pbtype in ('MESSAGE', 'MSG_W_CB'):
                target_fqn = member_desc.type_name.lstrip('.')
                target = self._resolve_payload(entry_desc, target_fqn,
                                               "oneof arm '%s'" % member_desc.name)
                if target.validate_header:
                    extra_headers.append(target.validate_header)
                access = prefix + Globals.naming_style.var_name(member_ir.name)
                routes.append(Route(Route.ONEOF_MESSAGE, case_label,
                                    target.fqn, target=target, access=access))
            else:
                # A scalar arm has no descriptor of its own; validating the
                # entrypoint (which the core always does) already covered it.
                routes.append(Route(Route.ONEOF_SCALAR, case_label,
                                    '%s (%s, covered by entrypoint validation)'
                                    % (member_desc.name, member_ir.pbtype)))

        if not routes:
            raise GeneratorError(
                "oneof '%s' in '%s' has no members, so there is nothing to route."
                % (oneof_name, entry_desc.fqn))

        return FilterSpec(
            entry_ref, Strategy.ONEOF, symbol_prefix,
            dispatch_expr='envelope.which_%s' % oneof_var,
            routes=routes,
            extra_headers=_dedupe(extra_headers))

    # -- any strategy -------------------------------------------------------

    def _build_any_spec(self, entry_desc, entry_ir, entry_ref, symbol_prefix):
        any_desc = any_payload_fields(entry_desc.desc)[0]

        any_ir = None
        for field in entry_ir.fields:
            if not isinstance(field, OneOf) and field.tag == any_desc.number:
                any_ir = field
                break
        if any_ir is None:
            raise GeneratorError(
                "nanopb did not generate a field for '%s.%s'; a filter cannot "
                "read its type_url." % (entry_desc.fqn, any_desc.name))

        if any_ir.allocation != 'STATIC':
            raise GeneratorError(
                "'%s.%s' has %s allocation. The filter needs a statically "
                "allocated google.protobuf.Any so it can read type_url and value "
                "directly; give google.protobuf.Any.type_url and "
                "google.protobuf.Any.value a max_size in your .options file."
                % (entry_desc.fqn, any_desc.name, any_ir.allocation))

        any_var = Globals.naming_style.var_name(any_ir.name)
        any_access = 'envelope.%s' % any_var
        presence = None
        if any_ir.rules == 'OPTIONAL':
            presence = 'envelope.%s' % Globals.naming_style.var_name('has_' + any_ir.name)

        allowed = self._any_allow_list(entry_desc, any_desc)

        routes = []
        extra_headers = []
        by_hash = OrderedDict()
        for type_url, target_fqn in allowed:
            target = self._resolve_payload(entry_desc, target_fqn,
                                           "Any allow-list entry '%s'" % type_url)
            if target.validate_header:
                extra_headers.append(target.validate_header)
            digest = type_url_hash(type_url)
            by_hash.setdefault(digest, []).append(type_url)
            routes.append(Route(Route.ANY_PAYLOAD, '0x%08XU' % digest,
                                type_url, target=target, access=any_access,
                                type_url=type_url))

        # Two allow-list entries that hash alike would emit duplicate case
        # labels and break the user's build with a confusing C error. Catch it
        # here, where we can explain it.
        collisions = [urls for urls in by_hash.values() if len(urls) > 1]
        if collisions:
            raise GeneratorError(
                "type_url hash collision in the Any allow-list: %s.\n"
                "The generated dispatch switch cannot distinguish them. Rename "
                "one of the payload messages, or narrow the allow-list."
                % '; '.join(' == '.join(urls) for urls in collisions))

        return FilterSpec(
            entry_ref, Strategy.ANY, symbol_prefix,
            dispatch_expr=any_access,
            presence_expr=presence,
            routes=routes,
            extra_headers=_dedupe(extra_headers))

    def _any_allow_list(self, entry_desc, any_desc):
        """The set of payload types the Any field is permitted to carry.

        An ``Any`` field is an open extension point, so a dispatch table can only
        be built from an explicit allow-list. In order of precedence:

        1. ``--filter-payloads``, when the user wants it in the build.
        2. ``(validate.rules).any.in`` on the field, which keeps the policy next
           to the schema and is also enforced by the runtime validator.

        "every message in this .proto file" is deliberately *not* an option: it
        makes the allow-list a side effect of file layout, so adding an unrelated
        message to the file silently widens the attack surface.
        """
        raw = None
        source = None
        if self.opts.filter_payloads:
            raw = list(self.opts.filter_payloads)
            source = '--filter-payloads'
        else:
            rules = field_validate_rules(any_desc)
            if rules is not None and rules.HasField('any') and list(rules.any.__getattribute__('in')):
                raw = list(rules.any.__getattribute__('in'))
                source = "(validate.rules).any.in on '%s.%s'" % (entry_desc.fqn, any_desc.name)

        if not raw:
            hint = ''
            rules = field_validate_rules(any_desc)
            if rules is not None and rules.HasField('any') and list(rules.any.not_in):
                hint = ("\nThe field declares any.not_in, but a deny-list cannot "
                        "produce a dispatch table: it says what is forbidden, not "
                        "what is decodable.")
            raise GeneratorError(
                "'%s.%s' is a google.protobuf.Any with no allow-list, so the "
                "filter has no safe set of payload types to decode.%s\n"
                "Declare the permitted types with (validate.rules).any.in on the "
                "field, or pass --filter-payloads=pkg.A;pkg.B."
                % (entry_desc.fqn, any_desc.name, hint))

        allowed = []
        seen = set()
        for item in raw:
            item = item.strip()
            if not item:
                continue
            # Accept "type.googleapis.com/pkg.Msg", "host/pkg.Msg" or "pkg.Msg".
            fqn = item.rsplit('/', 1)[-1].lstrip('.')
            type_url = item if '/' in item else '%s/%s' % (DEFAULT_TYPE_URL_HOST, fqn)
            if type_url in seen:
                continue
            seen.add(type_url)
            if not fqn:
                raise GeneratorError(
                    "%s contains '%s', which names no message type." % (source, item))
            allowed.append((type_url, fqn))

        if not allowed:
            raise GeneratorError("%s is empty; nothing could be allowed." % source)
        return allowed

    # -- shared -------------------------------------------------------------

    def _resolve_payload(self, entry_desc, fqn, what):
        entry = self.index.lookup(fqn)
        if entry is None:
            raise GeneratorError(
                "%s of '%s' refers to message '%s', which is not in the compiled "
                "descriptors. Import the .proto that defines it."
                % (what, entry_desc.fqn, fqn))
        ir_msg = ir_message_for_fqn(self.f, fqn)
        if ir_msg is None:
            raise GeneratorError(
                "%s of '%s' refers to message '%s', which nanopb did not generate "
                "a struct for in this compilation. The filter cannot decode it."
                % (what, entry_desc.fqn, fqn))
        return self._message_ref(fqn, ir_msg)

    def _message_ref(self, fqn, ir_msg):
        ctype = Globals.naming_style.type_name(ir_msg.name)
        init_zero = Globals.naming_style.define_name(str(ir_msg.name) + '_init_zero')
        msgdesc = '%s_msg' % ctype

        protofile = getattr(ir_msg, 'protofile', None)
        is_local = protofile is None or protofile.fdesc.name == self.f.fdesc.name

        if is_local:
            # Local messages on the filter path always get a validator: the
            # driver force-adds one, so the call below is guaranteed to link.
            validator = validator_func_name(ir_msg)
            header = None
        elif self.validator_lookup(protofile, ir_msg):
            validator = validator_func_name(ir_msg)
            header = validate_header_for(ir_msg)
        else:
            # The defining file generates no validator for this message, which
            # means it declares no rules: decoding it *is* the whole check.
            validator = None
            header = None

        return MessageRef(fqn, ctype, init_zero, msgdesc, validator, header)


def _dedupe(items):
    seen = set()
    out = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


# ---------------------------------------------------------------------------
#                              C emission
# ---------------------------------------------------------------------------


class FilterEmitter(object):
    """Render a :class:`FilterSpec` as C.

    Deliberately dependency-free: it receives a fully resolved spec and never
    inspects descriptors, the nanopb IR, or the command line.
    """

    def __init__(self, spec):
        self.spec = spec

    # -- header (.pb.h, insertion point "eof") ------------------------------

    def header_lines(self):
        spec = self.spec
        yield '\n'
        yield '#ifdef __cplusplus\n'
        yield 'extern "C" {\n'
        yield '#endif\n\n'

        yield '/* Packet filter for %s (%s dispatch).\n' % (spec.entry.fqn, spec.strategy)
        yield ' * Decodes, identifies and validates an untrusted buffer, and reports\n'
        yield ' * whether it may be handed on to the application.\n'
        yield ' */\n\n'

        yield '/**\n'
        yield ' * @brief Decode and validate a UDP datagram carrying %s.\n' % spec.entry.fqn
        yield ' *\n'
        yield ' * @param ctx           Optional user context (unused; reserved).\n'
        yield ' * @param packet        Pointer to the received datagram.\n'
        yield ' * @param packet_size   Length of the datagram in bytes.\n'
        yield ' * @return 0 to allow the packet, -1 to reject it.\n'
        yield ' */\n'
        yield '%s;\n\n' % spec.udp_signature

        yield '/**\n'
        yield ' * @brief Decode and validate a stream message carrying %s.\n' % spec.entry.fqn
        yield ' *\n'
        yield ' * @param ctx           Optional user context (unused; reserved).\n'
        yield ' * @param packet        Pointer to one complete framed message.\n'
        yield ' * @param packet_size   Length of the message in bytes.\n'
        yield ' * @param is_to_server  True if the direction is client -> server.\n'
        yield ' * @return 0 to allow the packet, -1 to reject it.\n'
        yield ' */\n'
        yield '%s;\n' % spec.tcp_signature

        yield '\n#ifdef __cplusplus\n'
        yield '} /* extern "C" */\n'
        yield '#endif\n'

    # -- includes (.pb.c, insertion point "includes") -----------------------

    def include_lines(self, protofile, options):
        """Includes the filter body needs, injected at the `includes` marker."""
        # options.libformat carries no trailing newline (it defaults to
        # '#include <%s>'), so each include has to be terminated explicitly.
        try:
            yield options.libformat % 'pb_decode.h'
        except TypeError:
            # no %s specified - use whatever was passed in as options.libformat
            yield options.libformat
        yield '\n'

        yield '#include "%s_validate.h"\n' % strip_proto_ext(protofile.fdesc.name)
        for header in self.spec.extra_headers:
            yield '#include "%s"\n' % header

    # -- source (.pb.c, insertion point "eof") ------------------------------

    def _reject_lines(self, indent, reason, with_violations=False):
        """Emit `return RET_REJECT;`, preceded (only in debug builds) by a
        log of why through the pluggable PB_VALIDATE_FILTER_LOG hook.

        The whole debug block is inside `#ifdef PB_VALIDATE_DEBUG`, so a
        normal (non-debug) build carries none of this: no extra code, no
        dependency on `violations` having been populated.
        """
        yield '%s#ifdef PB_VALIDATE_DEBUG\n' % indent
        if with_violations:
            yield '%s{\n' % indent
            yield '%s    pb_size_t __pb_vi;\n' % indent
            yield '%s    for (__pb_vi = 0; __pb_vi < violations.count; __pb_vi++) {\n' % indent
            yield ('%s        PB_VALIDATE_FILTER_LOG("%s: %%s %%s: %%s", '
                   'violations.violations[__pb_vi].field_path, '
                   'violations.violations[__pb_vi].constraint_id, '
                   'violations.violations[__pb_vi].message);\n') % (indent, reason)
            yield '%s    }\n' % indent
            yield '%s}\n' % indent
        else:
            yield '%sPB_VALIDATE_FILTER_LOG("%s");\n' % (indent, reason)
        yield '%s#endif\n' % indent
        yield '%sreturn %s;\n' % (indent, RET_REJECT)

    def source_lines(self):
        spec = self.spec

        yield '\n'
        yield '/* ---------------------------------------------------------------------\n'
        yield ' * Packet filter for %s\n' % spec.entry.fqn
        yield ' * Strategy: %s\n' % self._strategy_comment()
        yield ' * Policy:   unknown or undecodable input is rejected.\n'
        yield ' * --------------------------------------------------------------------- */\n'
        yield '\n'

        yield '%s\n' % spec.core_signature
        yield '{\n'
        yield '    pb_violations_t violations = {0};\n'
        yield '    pb_istream_t stream = pb_istream_from_buffer(packet, packet_size);\n'
        yield '    %s envelope = %s;\n' % (spec.entry.ctype, spec.entry.init_zero)
        yield '\n'
        yield '    if (!pb_decode(&stream, &%s, &envelope)) {\n' % spec.entry.msgdesc
        for line in self._reject_lines('        ', 'failed to decode %s' % spec.entry.fqn):
            yield line
        yield '    }\n'
        yield '\n'

        if spec.entry.validator_func:
            yield '    /* Validate the entrypoint before looking at its payload. */\n'
            yield '    if (!%s(&envelope, &violations)) {\n' % spec.entry.validator_func
            for line in self._reject_lines('        ', 'entrypoint validation failed', with_violations=True):
                yield line
            yield '    }\n'
            yield '\n'
        else:
            yield '    /* %s declares no validation rules; decoding is the whole check. */\n' % spec.entry.fqn
            yield '\n'

        if spec.strategy == Strategy.SINGLE:
            for line in self._single_dispatch():
                yield line
        elif spec.strategy == Strategy.ONEOF:
            for line in self._oneof_dispatch():
                yield line
        else:
            for line in self._any_dispatch():
                yield line

        yield '}\n'
        yield '\n'

        for line in self._wrappers():
            yield line

    def _strategy_comment(self):
        spec = self.spec
        if spec.strategy == Strategy.SINGLE:
            return 'every packet is decoded and validated as %s' % spec.entry.fqn
        if spec.strategy == Strategy.ONEOF:
            return ('dispatch on %s across %d oneof arm(s)'
                    % (spec.dispatch_expr, len(spec.routes)))
        return ('dispatch on google.protobuf.Any type_url across %d allowed type(s)'
                % len(spec.routes))

    def _single_dispatch(self):
        if not self.spec.entry.validator_func:
            yield '    (void)violations;\n'
        yield '    return %s;\n' % RET_ALLOW

    def _oneof_dispatch(self):
        spec = self.spec
        yield '    switch (%s) {\n' % spec.dispatch_expr
        for route in spec.routes:
            yield '        case %s: /* %s */\n' % (route.case_label, route.comment)
            if route.kind == Route.ONEOF_MESSAGE and route.target.validator_func:
                yield '            if (!%s(&%s, &violations)) {\n' % (
                    route.target.validator_func, route.access)
                for line in self._reject_lines('                ', '%s validation failed' % route.comment,
                                                with_violations=True):
                    yield line
                yield '            }\n'
            yield '            return %s;\n' % RET_ALLOW
            yield '\n'
        yield '        default:\n'
        yield '            /* No arm set, or an arm this build does not know. */\n'
        for line in self._reject_lines('            ', 'no oneof arm set, or an arm this build does not know'):
            yield line
        yield '    }\n'

    def _any_dispatch(self):
        spec = self.spec
        access = spec.dispatch_expr

        if spec.presence_expr:
            yield '    if (!%s) {\n' % spec.presence_expr
            for line in self._reject_lines('        ', 'no payload carried'):
                yield line
            yield '    }\n'
            yield '\n'

        yield '    {\n'
        yield '        const char *type_url = %s.type_url;\n' % access
        yield '        const char *cursor;\n'
        yield '        uint32_t type_hash = 0;\n'
        yield '\n'
        yield '        if (type_url[0] == \'\\0\') {\n'
        for line in self._reject_lines('            ', 'unidentified payload (empty type_url)'):
            yield line
        yield '        }\n'
        yield '\n'
        yield '        /* Cheap rolling hash so the switch below is a jump table; the\n'
        yield '         * strcmp inside each case is what actually decides identity. */\n'
        yield '        for (cursor = type_url; *cursor != \'\\0\'; cursor++) {\n'
        yield '            type_hash = type_hash * 31u + (uint32_t)(uint8_t)*cursor;\n'
        yield '        }\n'
        yield '\n'
        yield '        switch (type_hash) {\n'

        for route in spec.routes:
            target = route.target
            yield '            case %s: /* %s */\n' % (route.case_label, route.type_url)
            yield '                if (strcmp(type_url, "%s") == 0) {\n' % route.type_url
            yield '                    %s payload = %s;\n' % (target.ctype, target.init_zero)
            yield '                    pb_istream_t payload_stream = pb_istream_from_buffer(\n'
            yield '                        %s.value.bytes, %s.value.size);\n' % (access, access)
            yield '\n'
            yield '                    if (!pb_decode(&payload_stream, &%s, &payload)) {\n' % target.msgdesc
            for line in self._reject_lines('                        ', 'failed to decode payload for %s' % route.type_url):
                yield line
            yield '                    }\n'
            if target.validator_func:
                yield '                    if (!%s(&payload, &violations)) {\n' % target.validator_func
                for line in self._reject_lines('                        ', '%s payload validation failed' % route.type_url,
                                                with_violations=True):
                    yield line
                yield '                    }\n'
            yield '                    return %s;\n' % RET_ALLOW
            yield '                }\n'
            yield '                break;\n'
            yield '\n'

        yield '            default:\n'
        yield '                break;\n'
        yield '        }\n'
        yield '    }\n'
        yield '\n'
        yield '    /* type_url is not on the allow-list. */\n'
        for line in self._reject_lines('    ', 'type_url not on the allow-list'):
            yield line

    def _wrappers(self):
        """Transport shims over the transport-independent core."""
        spec = self.spec
        yield '%s\n' % spec.udp_signature
        yield '{\n'
        yield '    (void)ctx;\n'
        yield '    return %s_filter_core(packet, packet_size);\n' % spec.symbol_prefix
        yield '}\n'
        yield '\n'
        yield '%s\n' % spec.tcp_signature
        yield '{\n'
        yield '    (void)ctx;\n'
        yield '    (void)is_to_server;\n'
        yield '    return %s_filter_core(packet, packet_size);\n' % spec.symbol_prefix
        yield '}\n'


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
    validator_gen = nanopb_validator.ValidatorGenerator(f)

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
        if msg is not None and str(msg.name) not in validator_gen.validators:
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


# ---------------------------------------------------------------------------
#                            Command line handling
# ---------------------------------------------------------------------------


class FilterOptions(object):
    """This plugin's own configuration, kept apart from nanopb's options.

    The CLI describes *intent* -- which message is the protocol entrypoint, and
    what it is allowed to carry -- not the detection strategy the generator
    happens to use internally.
    """

    __slots__ = ('filter_messages', 'filter_mode', 'filter_payloads', 'entry_modes')

    def __init__(self, filter_message=None, filter_mode='auto', filter_payloads=(),
                 filter_messages=None, entry_modes=None):
        if filter_messages is None:
            filter_messages = (filter_message,) if filter_message else ()
        self.filter_messages = tuple(filter_messages)
        self.filter_mode = filter_mode
        self.filter_payloads = tuple(filter_payloads)
        # Per-entrypoint modes from "--filter=pkg.Msg:single;...".
        self.entry_modes = dict(entry_modes or {})

    @property
    def filter_message(self):
        """The entrypoint, when exactly one was requested (else the first)."""
        return self.filter_messages[0] if self.filter_messages else None

    @property
    def wants_filter(self):
        return bool(self.filter_messages)

    def for_entry(self, name):
        """Options describing just one of the requested entrypoints."""
        return FilterOptions(name, self.entry_modes.get(name, self.filter_mode),
                             self.filter_payloads)


#: Options owned by this plugin.  Everything else in the argument list is handed
#: straight to nanopb's own parser, so that -I/-x/-s/-C/--custom-style behave
#: identically here and in nanopb_generator.
OWN_OPTIONS = {
    '--filter': 'filter_message',
    '--filter-mode': 'filter_mode',
    '--filter-payloads': 'filter_payloads',
}

#: Options that used to exist and described the generator's internals rather
#: than the user's protocol.  Kept only to produce a useful error.
RETIRED_OPTIONS = {
    '--root-message':
        "use --filter=<fully.qualified.Message> (add --filter-mode=single to "
        "decode every packet as that message even if it declares a oneof)",
    '--envelope-name':
        "use --filter=<fully.qualified.Message>",
    '--envelope-mode':
        "use --filter-mode=auto|single|oneof|any; the entrypoint is named by "
        "--filter",
}


def split_own_options(args):
    """Separate this plugin's options from the ones nanopb should parse.

    Both "--opt=value" and "--opt value" spellings are accepted, matching how
    nanopb itself tolerates protoc's comma separation and shell-style splitting.
    """
    own = {}
    rest = []

    i = 0
    while i < len(args):
        arg = args[i]
        name, sep, value = arg.partition('=')

        if name in RETIRED_OPTIONS:
            raise GeneratorError(
                "%s is no longer supported: %s" % (name, RETIRED_OPTIONS[name]))

        if name in OWN_OPTIONS:
            if not sep:
                # "--opt value" form; consume the following argument
                if i + 1 >= len(args):
                    raise GeneratorError('%s requires a value' % name)
                value = args[i + 1]
                i += 1
            own[OWN_OPTIONS[name]] = value
        else:
            rest.append(arg)
        i += 1

    return build_filter_options(own), rest


def build_filter_options(raw):
    """Validate the raw strings collected by :func:`split_own_options`."""
    # ';' separates entrypoints and payload types, because protoc already
    # claims ',' for separating plugin options.
    # An entrypoint may carry its own mode: "pkg.Msg:single".
    filter_mode = raw.get('filter_mode', 'auto') or 'auto'
    payloads = raw.get('filter_payloads') or ''

    allowed_modes = ('auto',) + Strategy.ALL
    if filter_mode not in allowed_modes:
        raise GeneratorError(
            "--filter-mode must be one of %s, got: '%s'"
            % ('|'.join(allowed_modes), filter_mode))

    messages = []
    entry_modes = {}
    for item in (raw.get('filter_message') or '').split(';'):
        name, sep, mode = item.strip().partition(':')
        name, mode = name.strip(), mode.strip()
        if not name:
            continue
        if sep:
            if mode not in allowed_modes:
                raise GeneratorError(
                    "--filter=%s: mode must be one of %s, got: '%s'"
                    % (item.strip(), '|'.join(allowed_modes), mode))
            if 'filter_mode' in raw:
                raise GeneratorError(
                    "--filter=%s gives a mode and --filter-mode gives another; use one."
                    % item.strip())
            entry_modes[name] = mode
        messages.append(name)

    payload_list = [item.strip() for item in payloads.split(';') if item.strip()]

    duplicates = sorted(set(m for m in messages if messages.count(m) > 1))
    if duplicates:
        raise GeneratorError("--filter lists %s more than once." % ', '.join(duplicates))

    if len(messages) > 1:
        # Mode and allow-list describe one protocol shape; applying them to
        # several entrypoints at once would silently guess for all but one.
        if 'filter_mode' in raw or payload_list:
            raise GeneratorError(
                "--filter-mode and --filter-payloads apply to a single entrypoint, "
                "but --filter names %d (%s). Generate those filters separately."
                % (len(messages), '; '.join(messages)))

    if not messages:
        if 'filter_mode' in raw:
            raise GeneratorError(
                "--filter-mode was given without --filter. Name the protocol "
                "entrypoint with --filter=<fully.qualified.Message>.")
        if payload_list:
            raise GeneratorError(
                "--filter-payloads was given without --filter. Name the protocol "
                "entrypoint with --filter=<fully.qualified.Message>.")

    return FilterOptions(filter_mode=filter_mode, filter_payloads=payload_list,
                         filter_messages=messages, entry_modes=entry_modes)


def parse_plugin_parameter(parameter):
    """Split a protoc plugin parameter string into an argument list.

    Mirrors nanopb_generator.main_plugin so that both plugins accept exactly
    the same spellings.
    """
    try:
        # Versions of Python prior to 2.7.3 do not support unicode
        # input to shlex.split(). Try to convert to str if possible.
        params = str(parameter)
    except UnicodeEncodeError:
        params = parameter

    if ',' not in params and ' -' in params:
        # Nanopb has traditionally supported space as separator in options
        return shlex.split(params)

    # Protoc separates options passed to plugins by comma.
    # This allows also giving --nanopb-validate_opt option multiple times.
    lex = shlex.shlex(params)
    lex.whitespace_split = True
    lex.whitespace = ','
    lex.commenters = ''
    return list(lex)


# ---------------------------------------------------------------------------
#                              Plugin entry point
# ---------------------------------------------------------------------------


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
    force = _dedupe(name for spec in specs for name in spec.required_validators())
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

        if nanopb_validator is None:
            raise GeneratorError("nanopb_validator module is not available; "
                                 "cannot generate validation code.")

        nanopb.optparser.usage = ("protoc --nanopb-validate_out=outdir "
                                  "[--nanopb-validate_opt=option] file.proto")
        options, _ = nanopb.process_cmdline(nanopb_args, is_plugin=True)

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
                        entry.content = content

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
    except nanopb_validator.ValidationRuleNotImplementedError as e:
        # A declared validate.proto option has no C-runtime enforcement yet
        # (see nanopb_validator.RuleEmitterRegistry.emit and the guard checks
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
