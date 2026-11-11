"""Model shared by the packet-filter generator: descriptor index, message references and
routes, FilterSpec (one resolved filter) and drop lines.
"""

from __future__ import unicode_literals

import os
import sys

from collections import OrderedDict

# nanopb's generator (read-only, from the checkout this tool lives in) does the
# descriptor parsing, option handling and naming styles; env.setup() puts it
# on sys.path and builds nanopb_pb2 and our validate_pb2.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import env  # noqa: E402
env.setup()

import nanopb_api as nanopb  # noqa: E402  (everything used from nanopb is listed there)
import validate_pb2  # noqa: E402

OneOf = nanopb.OneOf


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
    only thing :mod:`validator` needs from us.

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


def drop_line(indent, public_name, reason):
    """The drop log: every build, through PB_VALIDATE_FILTER_DROP (pb_validate.h)."""
    return '%sPB_VALIDATE_FILTER_DROP("%s", "%s");\n' % (indent, public_name, reason.replace('"', "'"))


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
                 'presence_expr', 'routes', 'extra_headers', 'public_name')

    def __init__(self, entry, strategy, symbol_prefix, dispatch_expr=None,
                 presence_expr=None, routes=(), extra_headers=()):
        self.entry = entry
        self.strategy = strategy
        self.symbol_prefix = symbol_prefix
        self.dispatch_expr = dispatch_expr
        self.presence_expr = presence_expr
        self.routes = tuple(routes)
        self.extra_headers = tuple(extra_headers)
        # Entry points are <public_name>_udp / _tcp (--filter-name renames them).
        self.public_name = symbol_prefix + '_filter'

    @property
    def udp_signature(self):
        return ('int %s_udp(void *ctx, const uint8_t *packet, size_t packet_size)'
                % self.public_name)

    @property
    def tcp_signature(self):
        return ('int %s_tcp(void *ctx, const uint8_t *packet, size_t packet_size, '
                'bool is_to_server)' % self.public_name)

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
    """Name of the ``pb_validate_*`` function the validator emits for a message."""
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


def _dedupe(items):
    seen = set()
    out = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


# ---------------------------------------------------------------------------
#                              Plugin entry point
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
#                    Protocol filter (--protocol-filter=NAME)
# ---------------------------------------------------------------------------
#
# One NAME_filter_udp/_tcp for a whole protocol: the packet is a
# google.protobuf.Any and its type_url is the opcode. A switch on the type_url
# selects the message, which is decoded and validated; every Any inside it is
# resolved the same way, up to PB_VALIDATE_FILTER_MAX_ANY_DEPTH levels.

ANY_FQN = 'google.protobuf.Any'
