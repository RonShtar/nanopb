"""Options of the nanopb-validate plugin (--filter, --filter-mode, --protocol-filter,
--filter-name, ...) and parsing of the protoc plugin parameter.
"""

from __future__ import unicode_literals

import os
import re
import shlex
import sys


# nanopb's generator (read-only, from the checkout this tool lives in) does the
# descriptor parsing, option handling and naming styles; env.setup() puts it
# on sys.path and builds nanopb_pb2 and our validate_pb2.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import env  # noqa: E402
env.setup()


from filter_model import (GeneratorError, Strategy)  # noqa: E402


# ---------------------------------------------------------------------------
#                            Command line handling
# ---------------------------------------------------------------------------


class FilterOptions(object):
    """This plugin's own configuration, kept apart from nanopb's options.

    The CLI describes *intent* -- which message is the protocol entrypoint, and
    what it is allowed to carry -- not the detection strategy the generator
    happens to use internally.
    """

    __slots__ = ('filter_messages', 'filter_mode', 'filter_payloads', 'entry_modes',
                 'protocol_filter', 'protocol_messages', 'filter_name')

    def __init__(self, filter_message=None, filter_mode='auto', filter_payloads=(),
                 filter_messages=None, entry_modes=None, protocol_filter=None,
                 filter_name=None):
        if filter_messages is None:
            filter_messages = (filter_message,) if filter_message else ()
        self.filter_messages = tuple(filter_messages)
        self.filter_mode = filter_mode
        self.filter_payloads = tuple(filter_payloads)
        # Per-entrypoint modes from "--filter=pkg.Msg:single;...".
        self.entry_modes = dict(entry_modes or {})
        # --protocol-filter=NAME: one Any-dispatched filter for every message.
        self.protocol_filter = protocol_filter
        self.protocol_messages = ()
        # --filter-name=NAME: entry points exactly NAME_udp / NAME_tcp.
        self.filter_name = filter_name

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
    '--protocol-filter': 'protocol_filter',
    '--filter-name': 'filter_name',
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

    protocol_filter = (raw.get('protocol_filter') or '').strip() or None
    if protocol_filter is not None and not re.match(r'^[A-Za-z_][A-Za-z0-9_]*$', protocol_filter):
        raise GeneratorError("--protocol-filter=%s: the name must be a C identifier "
                             "(it prefixes <name>_filter_udp/_tcp)." % protocol_filter)

    filter_name = (raw.get('filter_name') or '').strip() or None
    if filter_name is not None:
        if not re.match(r'^[A-Za-z_][A-Za-z0-9_]*$', filter_name):
            raise GeneratorError("--filter-name=%s: the name must be a C identifier "
                                 "(the entry points are <name>_udp / <name>_tcp)." % filter_name)
        if protocol_filter is None and len(messages) != 1:
            raise GeneratorError("--filter-name names one filter: give it with --protocol-filter, "
                                 "or with exactly one --filter entrypoint.")

    return FilterOptions(filter_mode=filter_mode, filter_payloads=payload_list,
                         filter_messages=messages, entry_modes=entry_modes,
                         protocol_filter=protocol_filter, filter_name=filter_name)


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
