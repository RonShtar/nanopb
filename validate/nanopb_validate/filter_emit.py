"""C emission for packet filters: per-entrypoint filters (FilterEmitter, spliced into
nanopb's .pb.c/.h) and protocol filters (ProtocolFilterEmitter, <name>_filter.c/.h).
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
import c_layout  # noqa: E402

Globals = nanopb.Globals
from filter_model import (ANY_FQN, GeneratorError, RET_ALLOW, RET_REJECT, Route, Strategy,  # noqa: E402
                          drop_line, ir_message_for_fqn,
                          strip_proto_ext, type_url_hash, validator_func_name)


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
        yield drop_line(indent, self.spec.public_name, reason)
        if with_violations:
            yield '#ifdef PB_VALIDATE_DEBUG\n'
            yield '%s{\n' % indent
            yield '%s    pb_size_t pbv_vi;\n' % indent
            yield '%s    for (pbv_vi = 0; pbv_vi < violations->count; pbv_vi++) {\n' % indent
            yield ('%s        PB_VALIDATE_FILTER_RULE("%s", '
                   'violations->violations[pbv_vi].field_path, '
                   'violations->violations[pbv_vi].constraint_id, '
                   'violations->violations[pbv_vi].message);\n') % (indent, reason)
            yield '%s    }\n' % indent
            yield '%s}\n' % indent
            yield '#endif\n'
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
        yield '#ifdef PB_VALIDATE_DEBUG\n'
        yield '    pb_violations_t violations_buffer;\n'
        yield '    pb_violations_t *violations = &violations_buffer;\n'
        yield '#else\n'
        yield '    /* Release builds only need pass/fail: no violations buffer to fill. */\n'
        yield '    pb_violations_t *violations = NULL;\n'
        yield '#endif\n'
        yield '    pb_istream_t stream = pb_istream_from_buffer(packet, packet_size);\n'
        for line in self._decode_buffer('    ', spec.entry.ctype, 'envelope'):
            yield line
        yield '\n'
        yield '#ifdef PB_VALIDATE_DEBUG\n'
        yield '    pb_violations_init(violations);\n'
        yield '#endif\n'
        yield '    if (!pb_decode(&stream, &%s, &envelope)) {\n' % spec.entry.msgdesc
        for line in self._reject_lines('        ', 'failed to decode %s' % spec.entry.fqn):
            yield line
        yield '    }\n'
        yield '\n'

        if spec.entry.validator_func:
            yield '    /* Validate the entrypoint before looking at its payload. */\n'
            yield '    if (!%s(&envelope, violations)) {\n' % spec.entry.validator_func
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

    @staticmethod
    def _decode_buffer(indent, ctype, name):
        """Declare the struct a packet is decoded into.

        pb_decode() initializes every field itself, so no _init_zero copy is
        needed. PB_VALIDATE_FILTER_STATIC_BUFFERS moves the struct out of the
        stack (smaller stack, but the filter is then not reentrant).
        """
        yield '#ifdef PB_VALIDATE_FILTER_STATIC_BUFFERS\n'
        yield '%sstatic %s %s;\n' % (indent, ctype, name)
        yield '#else\n'
        yield '%s%s %s;\n' % (indent, ctype, name)
        yield '#endif\n'

    def _single_dispatch(self):
        if not self.spec.entry.validator_func:
            yield '    (void)violations;\n'
        yield '    return %s;\n' % RET_ALLOW

    def _oneof_dispatch(self):
        spec = self.spec
        yield '    switch (%s) {\n' % spec.dispatch_expr
        for route in spec.routes:
            yield '        case %s: /* %s */\n' % (route.case_label, route.comment)
            if route.kind == Route.ONEOF_MESSAGE and route.target.validator_func and \
                    not spec.entry.validator_func:
                yield '            if (!%s(&%s, violations)) {\n' % (
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
            for line in self._decode_buffer('                    ', target.ctype, 'payload'):
                yield line
            yield '                    pb_istream_t payload_stream = pb_istream_from_buffer(\n'
            yield '                        %s.value.bytes, %s.value.size);\n' % (access, access)
            yield '\n'
            yield '                    if (!pb_decode(&payload_stream, &%s, &payload)) {\n' % target.msgdesc
            for line in self._reject_lines('                        ', 'failed to decode payload for %s' % route.type_url):
                yield line
            yield '                    }\n'
            if target.validator_func:
                yield '                    if (!%s(&payload, violations)) {\n' % target.validator_func
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


class ProtocolFilterEmitter(object):
    """Emit NAME_filter.h / NAME_filter.c for every message of a protocol."""

    def __init__(self, name, hub, index, messages, pb_headers, validate_headers, public_name=None):
        self.name = name
        # --filter-name NAME: exactly NAME_udp / _tcp; without it <name>_filter_udp / _tcp.
        self.public_name = public_name or (name + '_filter')
        self.hub = hub                  # ProtoFile that knows every message of the request
        self.index = index              # DescriptorIndex
        self.messages = messages        # protocol message FQNs, in declaration order
        self.pb_headers = pb_headers
        self.validate_headers = validate_headers
        self.any_ir = ir_message_for_fqn(hub, ANY_FQN)
        if self.any_ir is None:
            raise GeneratorError(
                "--protocol-filter=%s: the packet is a google.protobuf.Any, so "
                "google/protobuf/any.proto must be generated in the same invocation."
                % name)
        self._check_any_storage()
        self._holds_any = {}

    # -- model ----------------------------------------------------------------

    def _check_any_storage(self):
        fields = dict((f.name, f) for f in self.any_ir.fields)
        for name in ('type_url', 'value'):
            if fields[name].allocation != 'STATIC':
                raise GeneratorError(
                    "--protocol-filter needs static storage for google.protobuf.Any.%s; "
                    "give it a max_size in google/protobuf/any.options." % name)

    def ir(self, ctype):
        return self.hub.dependencies.get(str(ctype))

    def is_any(self, field):
        return self.ir(field.ctype) is self.any_ir

    @staticmethod
    def plain_fields(msg):
        for field in msg.fields:
            if field.pbtype == 'oneof':
                for member in field.fields:
                    yield field, member
            else:
                yield None, field

    def holds_any(self, msg, active=()):
        """Does `msg` contain an Any anywhere (sub-messages included)?"""
        key = str(msg.name)
        if key in self._holds_any:
            return self._holds_any[key]
        if key in active:
            return False  # recursion: the other path through it decides
        found = False
        for _, field in self.plain_fields(msg):
            if field.pbtype not in ('MESSAGE', 'MSG_W_CB'):
                continue
            sub = self.ir(field.ctype)
            if sub is self.any_ir or (sub is not None and self.holds_any(sub, active + (key,))):
                found = True
                break
        self._holds_any[key] = found
        return found

    def ctype(self, msg):
        return Globals.naming_style.type_name(msg.name)

    def check_func(self, msg):
        return '%s_check_%s' % (self.name, self.ctype(msg))

    # -- emission -------------------------------------------------------------

    def header(self):
        guard = 'PB_PROTOCOL_FILTER_%s_H_INCLUDED' % self.name.upper()
        yield '/* Packet filter for protocol %s, generated by nanopb-validate --protocol-filter. */\n' % self.name
        yield '#ifndef %s\n#define %s\n\n' % (guard, guard)
        yield c_layout.lib_include('pb.h') + '\n'
        yield '#ifdef __cplusplus\nextern "C" {\n#endif\n\n'
        what = (' * The packet is a google.protobuf.Any; its type_url selects one of the\n'
                ' * %d messages of the protocol, which is decoded and validated. Every Any\n'
                ' * inside it is resolved the same way, up to PB_VALIDATE_FILTER_MAX_ANY_DEPTH\n'
                ' * levels. Unknown type_urls are rejected, and every drop is logged through\n'
                ' * PB_VALIDATE_FILTER_DROP.\n' % len(self.messages))
        yield '/**\n'
        yield ' * @brief Decode and validate one %s UDP datagram.\n' % self.name
        yield ' *\n'
        yield what
        yield ' *\n'
        yield ' * @param ctx           Optional user context (unused; reserved).\n'
        yield ' * @param packet        Pointer to the received datagram.\n'
        yield ' * @param packet_size   Length of the datagram in bytes.\n'
        yield ' * @return 0 to allow the packet, -1 to drop it.\n'
        yield ' */\n'
        yield 'int %s_udp(void *ctx, const uint8_t *packet, size_t packet_size);\n\n' % self.public_name
        yield '/**\n'
        yield ' * @brief Decode and validate one %s message received over TCP.\n' % self.name
        yield ' *\n'
        yield what
        yield ' *\n'
        yield ' * @param ctx           Optional user context (unused; reserved).\n'
        yield ' * @param packet        Pointer to one complete framed message.\n'
        yield ' * @param packet_size   Length of the message in bytes.\n'
        yield ' * @param is_to_server  True if the direction is client -> server.\n'
        yield ' * @return 0 to allow the message, -1 to drop it.\n'
        yield ' */\n'
        yield 'int %s_tcp(void *ctx, const uint8_t *packet, size_t packet_size, bool is_to_server);\n\n' % self.public_name
        yield '#ifdef __cplusplus\n} /* extern "C" */\n#endif\n\n'
        yield '#endif /* %s */\n' % guard

    def _reject(self, indent, reason):
        yield drop_line(indent, self.public_name, reason)
        yield '%sreturn %s;\n' % (indent, RET_REJECT)

    def _visit(self, indent, field, access):
        """Statements that check one Any field or one sub-message holding Any."""
        if field.allocation != 'STATIC':
            raise GeneratorError(
                "--protocol-filter: field '%s' of %s holds a google.protobuf.Any but has %s "
                "storage, which the filter cannot inspect. Give it max_size/max_count."
                % (field.name, field.struct_name, field.allocation.lower()))
        sub = self.ir(field.ctype)
        func = '%s_check_any' % self.name if sub is self.any_ir else self.check_func(sub)
        if field.rules == 'REPEATED':
            count = '%s_count' % access
        elif field.rules == 'FIXARRAY':
            count = '(pb_size_t)(sizeof(%s) / sizeof(%s[0]))' % (access, access)
        else:
            count = None
        if count is None:
            return ['%sif (%s(&%s, depth) != 0) return %s;\n' % (indent, func, access, RET_REJECT)]
        return ['%s{\n' % indent,
                '%s    pb_size_t i;\n' % indent,
                '%s    for (i = 0; i < %s; i++)\n' % (indent, count),
                '%s        if (%s(&%s[i], depth) != 0) return %s;\n' % (indent, func, access, RET_REJECT),
                '%s}\n' % indent]

    def _check_body(self, msg):
        lines = []
        for field in msg.fields:
            if field.pbtype == 'oneof':
                arms = []
                for member in field.fields:
                    sub = self.ir(member.ctype) if member.pbtype in ('MESSAGE', 'MSG_W_CB') else None
                    if sub is None or not (sub is self.any_ir or self.holds_any(sub)):
                        continue
                    access = ('msg->%s' % member.name) if field.anonymous else ('msg->%s.%s' % (field.name, member.name))
                    arms.append(['        case %s_%s_tag:\n' % (msg.name, member.name)] +
                                self._visit('            ', member, access) + ['            break;\n'])
                if arms:
                    lines.append('    switch (msg->which_%s) {\n' % field.name)
                    for arm in arms:
                        lines += arm
                    lines.append('        default:\n            break;\n    }\n')
                continue
            if field.pbtype not in ('MESSAGE', 'MSG_W_CB'):
                continue
            sub = self.ir(field.ctype)
            if sub is None or not (sub is self.any_ir or self.holds_any(sub)):
                continue
            access = 'msg->%s' % field.name
            if field.rules == 'OPTIONAL':
                lines.append('    if (msg->has_%s) {\n' % field.name)
                lines += self._visit('        ', field, access)
                lines.append('    }\n')
            else:
                lines += self._visit('    ', field, access)
        return lines

    def _protocol_irs(self):
        result = []
        for fqn in self.messages:
            msg = ir_message_for_fqn(self.hub, fqn)
            if msg is not None:
                result.append((fqn, msg))
        return result

    def source(self):
        name = self.name
        yield '/* Packet filter for protocol %s, generated by nanopb-validate --protocol-filter. */\n' % name
        yield '#include "%s_filter.h"\n' % name
        yield '#include <string.h>\n'
        yield c_layout.lib_include('pb_decode.h')
        for header in self.pb_headers:
            yield '#include "%s"\n' % header
        for header in self.validate_headers:
            yield '#include "%s"\n' % header
        yield '\n'
        yield '/* Levels of google.protobuf.Any resolved inside each other (stack use grows\n'
        yield ' * with it: one decoded payload struct per level). */\n'
        yield '#ifndef PB_VALIDATE_FILTER_MAX_ANY_DEPTH\n#define PB_VALIDATE_FILTER_MAX_ANY_DEPTH 4\n#endif\n\n'

        any_ctype = self.ctype(self.any_ir)
        yield 'static int %s_check_any(const %s *any, int depth);\n' % (name, any_ctype)

        # Every message that holds an Any gets a walker (protocol messages and
        # anything they reach, e.g. map entries), declared up front for recursion.
        walkers = []
        seen = set()
        pending = [msg for _, msg in self._protocol_irs()]
        while pending:
            msg = pending.pop(0)
            if str(msg.name) in seen or msg is self.any_ir or not self.holds_any(msg):
                continue
            seen.add(str(msg.name))
            walkers.append(msg)
            for _, field in self.plain_fields(msg):
                if field.pbtype in ('MESSAGE', 'MSG_W_CB'):
                    sub = self.ir(field.ctype)
                    if sub is not None:
                        pending.append(sub)
        for msg in walkers:
            yield 'static int %s(const %s *msg, int depth);\n' % (self.check_func(msg), self.ctype(msg))
        yield '\n'
        for msg in walkers:
            yield '/* Resolve the google.protobuf.Any fields of %s. */\n' % msg.name
            yield 'static int %s(const %s *msg, int depth)\n{\n' % (self.check_func(msg), self.ctype(msg))
            for line in self._check_body(msg):
                yield line
            yield '    (void)depth;\n'
            yield '    return %s;\n}\n\n' % RET_ALLOW

        cases = OrderedDict()
        for fqn, msg in self._protocol_irs():
            cases.setdefault(type_url_hash(fqn), []).append((fqn, msg))

        yield '/* The type_url is the opcode: it selects the message to decode and validate. */\n'
        yield 'static int %s_check_any(const %s *any, int depth)\n{\n' % (name, any_ctype)
        yield '    const char *type_name = strrchr(any->type_url, \'/\');\n'
        yield '    const char *cursor;\n'
        yield '    uint32_t hash = 0;\n\n'
        yield '    if (depth >= PB_VALIDATE_FILTER_MAX_ANY_DEPTH) {\n'
        for line in self._reject('        ', 'google.protobuf.Any nested too deep'):
            yield line
        yield '    }\n'
        yield '    /* "type.googleapis.com/pkg.Msg" -> "pkg.Msg"; any host prefix is accepted. */\n'
        yield '    type_name = type_name ? type_name + 1 : any->type_url;\n'
        yield '    for (cursor = type_name; *cursor != \'\\0\'; cursor++)\n'
        yield '        hash = hash * 31u + (uint32_t)(uint8_t)*cursor;\n\n'
        yield '    switch (hash) {\n'
        for value, entries in cases.items():
            yield '        case 0x%08xu:\n' % value
            for fqn, msg in entries:
                ctype = self.ctype(msg)
                yield '            if (strcmp(type_name, "%s") == 0) {\n' % fqn
                yield '                %s payload;\n' % ctype
                yield '                pb_istream_t stream = pb_istream_from_buffer(any->value.bytes, any->value.size);\n'
                yield '                if (!pb_decode(&stream, &%s_msg, &payload)) {\n' % ctype
                for line in self._reject('                    ', 'cannot decode %s' % fqn):
                    yield line
                yield '                }\n'
                yield '                if (!%s(&payload, NULL)) {\n' % validator_func_name(msg)
                for line in self._reject('                    ', '%s validation failed' % fqn):
                    yield line
                yield '                }\n'
                if str(msg.name) in seen:
                    yield '                return %s(&payload, depth + 1);\n' % self.check_func(msg)
                else:
                    yield '                return %s;\n' % RET_ALLOW
                yield '            }\n'
            yield '            break;\n'
        yield '        default:\n            break;\n    }\n'
        for line in self._reject('    ', 'type_url is not a message of this protocol'):
            yield line
        yield '}\n\n'

        yield 'static int %s_filter_core(const uint8_t *packet, size_t packet_size)\n{\n' % name
        yield '#ifdef PB_VALIDATE_FILTER_STATIC_BUFFERS\n'
        yield '    static %s any;\n' % any_ctype
        yield '#else\n'
        yield '    %s any;\n' % any_ctype
        yield '#endif\n'
        yield '    pb_istream_t stream = pb_istream_from_buffer(packet, packet_size);\n\n'
        yield '    if (!pb_decode(&stream, &%s_msg, &any)) {\n' % any_ctype
        for line in self._reject('        ', 'packet is not a google.protobuf.Any'):
            yield line
        yield '    }\n'
        yield '    return %s_check_any(&any, 0);\n}\n\n' % name

        public = self.public_name
        yield 'int %s_udp(void *ctx, const uint8_t *packet, size_t packet_size)\n{\n' % public
        yield '    (void)ctx;\n    return %s_filter_core(packet, packet_size);\n}\n\n' % name
        yield 'int %s_tcp(void *ctx, const uint8_t *packet, size_t packet_size, bool is_to_server)\n{\n' % public
        yield '    (void)ctx;\n    (void)is_to_server;\n    return %s_filter_core(packet, packet_size);\n}\n' % name


def protocol_messages(index, files):
    """FQNs of the messages a protocol filter accepts: every message of `files`
    except map entries and google.protobuf well-known types."""
    result = []
    for entry in index.by_fqn.values():
        if entry.filename not in files or entry.fqn.startswith('google.protobuf.'):
            continue
        if entry.desc.options.map_entry:
            continue
        result.append(entry.fqn)
    return result
