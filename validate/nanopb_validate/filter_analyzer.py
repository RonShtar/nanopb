"""ProtocolAnalyzer: from the descriptors and options, decide how each filter entrypoint
dispatches (single, oneof or google.protobuf.Any) and build its FilterSpec.
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

Globals = nanopb.Globals
OneOf = nanopb.OneOf
from filter_model import (DEFAULT_TYPE_URL_HOST, FilterSpec, GeneratorError, MessageRef, Route, Strategy,  # noqa: E402
                          _dedupe, any_payload_fields, field_validate_rules, ir_message_for_fqn,
                          oneof_members, real_oneof_indices, type_url_hash, validate_header_for,
                          validator_func_name)


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
