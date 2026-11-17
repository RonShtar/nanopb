"""Exact static storage for google.protobuf.Any, per protocol.

* type_url: the longest "type.googleapis.com/<message>" of the protocol's files and
  imports (nested messages too), or a longer any.in URL, plus the NUL.
* value: the largest maximum encoded size nanopb itself computes (its
  `#define <msg>_size N`) of the messages that hold no Any. A message that carries an
  Any has no fixed maximum once Anys nest, so it is not counted: it fits when its
  actual encoding is that small. `--any-value-size N` sets value instead.

gen writes both into the .options nanopb reads first; the data generator gets the
same file, so test packets fit the C structs.
"""

import os
import re
import shutil
import subprocess
import tempfile

import env
from protos import BackendError, OPTION_PROTOS, field_rules, is_option_proto

ANY_PROTO = 'google/protobuf/any.proto'
ANY_TYPE = '.google.protobuf.Any'
TYPE_URL_PREFIX = 'type.googleapis.com/'
SIZE_RE = re.compile(r'^#define (\w+)_size\s+(\d+)\s*$', re.M)
ANY_FIELD_RE = r'^(\S*google\.protobuf\.Any\.%s\s+.*?)\bmax_size\s*:\s*\d+(.*)$'


def uses_any(unit):
    return any(f.name == ANY_PROTO for f in unit.fds.file)


def own_messages(unit):
    """{full name: DescriptorProto} of every message of the protocol and its imports."""

    found = {}

    def walk(prefix, messages):
        for msg in messages:
            name = prefix + msg.name
            found[name] = msg
            walk(name + '.', msg.nested_type)

    for fdesc in unit.fds.file:
        if not is_option_proto(fdesc.name) and fdesc.name != ANY_PROTO:
            walk(fdesc.package + '.' if fdesc.package else '', fdesc.message_type)
    return found


def any_holders(messages):
    """Full names of the messages that contain a google.protobuf.Any, directly or in a sub-message."""

    holders = set()
    changed = True
    while changed:
        changed = False
        for name, msg in messages.items():
            if name in holders:
                continue
            for fld in msg.field:
                target = fld.type_name.lstrip('.')
                if fld.type_name == ANY_TYPE or target in holders:
                    holders.add(name)
                    changed = True
                    break
    return holders


def longest_type_url(unit):
    """(storage size, URL) for Any.type_url."""

    longest = TYPE_URL_PREFIX
    for name, msg in own_messages(unit).items():
        if not msg.options.map_entry and len(TYPE_URL_PREFIX + name) > len(longest):
            longest = TYPE_URL_PREFIX + name
        for fld in msg.field:
            rules = field_rules(fld)
            if rules is not None and rules.HasField('any'):
                for url in getattr(rules.any, 'in'):
                    if len(url) > len(longest):
                        longest = url
    if len(TYPE_URL_PREFIX + 'google.protobuf.Any') > len(longest):
        longest = TYPE_URL_PREFIX + 'google.protobuf.Any'
    return len(longest) + 1, longest


def measured_sizes(unit):
    """{C name: maximum encoded size} as nanopb computes it, from one nanopb-only run."""

    return _measure(unit, None)


def _measure(unit, any_options_text):
    """measured_sizes(), with ``any_options_text`` as google/protobuf/any.options when given."""

    outdir = tempfile.mkdtemp(prefix='nanopb_ws_size_')
    try:
        includes = [p for p in unit.includes if os.path.isdir(p)]
        first = []
        if any_options_text is not None:
            optdir = os.path.join(outdir, '_options')
            os.makedirs(os.path.join(optdir, 'google', 'protobuf'))
            with open(os.path.join(optdir, 'google', 'protobuf', 'any.options'), 'w', newline='\n') as handle:
                handle.write(any_options_text)
            first = [optdir]
        opts = ['-I' + p for p in first + includes] + ['-q']
        for name in sorted(set(OPTION_PROTOS) | set(f.name for f in unit.fds.file if is_option_proto(f.name))):
            opts += ['-x', name]
        cmd = env.protoc_command() + ['-I' + p for p in includes]
        cmd += ['--nanopb_opt=' + o for o in opts] + ['--nanopb_out=' + outdir] + unit.generated_files()
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              universal_newlines=True, cwd=outdir, env=env.subprocess_env())
        if proc.returncode != 0:
            raise BackendError('measuring message sizes failed for unit %s:\n%s' % (unit.name, proc.stdout))
        sizes = {}
        for root, dirs, files in os.walk(outdir):
            dirs[:] = [d for d in dirs if d != '_options']
            for name in files:
                if name.endswith('.pb.h'):
                    with open(os.path.join(root, name), encoding='utf-8') as handle:
                        sizes.update((m, int(n)) for m, n in SIZE_RE.findall(handle.read()))
        return sizes
    finally:
        shutil.rmtree(outdir, ignore_errors=True)


def largest_payload(unit, sizes):
    """(bytes, message) of the largest message that holds no Any; (None, None) if none is bounded."""

    messages = own_messages(unit)
    holders = any_holders(messages)
    best, best_name = None, None
    for name, msg in messages.items():
        if msg.options.map_entry or name in holders:
            continue
        size = sizes.get(name.replace('.', '_'))
        if size is not None and (best is None or size > best):
            best, best_name = size, name
    return best, best_name


def exact_any_sizes(unit):
    """{'type_url': (size, URL), 'value': (size, why)} for the unit's Any; None without Any.

    Computed once per Unit. unit.any_value_override (--any-value-size) wins for value."""

    if not uses_any(unit):
        return None
    cached = getattr(unit, '_any_sizes', None)
    if cached is not None:
        return cached
    result = {'type_url': longest_type_url(unit), 'deeper': []}
    override = getattr(unit, 'any_value_override', None)
    if override:
        result['value'] = (int(override), '--any-value-size')
        unit._any_sizes = result
        return result

    messages = own_messages(unit)
    holders = set(n for n in any_holders(messages) if not messages[n].options.map_entry)
    # Pass 1: the largest message that holds no Any (its size does not depend on Any).
    leaf, leaf_name = largest_payload(unit, measured_sizes(unit))
    leaf = max(leaf or 0, 1)                  # an Any of an empty message has an empty value
    value, why = leaf, ('the largest message without an Any: %s (%s_size)'
                        % (leaf_name, leaf_name.replace('.', '_')) if leaf_name else 'no bounded message')
    if holders:
        # Pass 2: nanopb's sizes of the messages that carry Anys, with each of those Anys
        # holding the largest message without one: one level of nesting always fits.
        probe = dict(result, value=(leaf, ''))
        sizes = _measure(unit, exact_options(project_any_options(unit), 'google.protobuf', probe))
        for name in sorted(holders):
            size = sizes.get(name.replace('.', '_'))
            if size is not None and size > value:
                value, why = size, ('%s (%s_size) with its Anys holding the largest message without '
                                    'an Any, %s' % (name, name.replace('.', '_'), leaf_name))
        result['deeper'] = deeper_nesting(messages, holders)
    result['value'] = (value, why)
    unit._any_sizes = result
    return result


def deeper_nesting(messages, holders):
    """['pkg.Msg.field', ...]: Any fields that may hold a message carrying an Any itself
    (no any.in list, or one that allows such a message), i.e. two levels of nesting."""

    found = []
    for name, msg in sorted(messages.items()):
        for fld in msg.field:
            if fld.type_name != ANY_TYPE:
                continue
            rules = field_rules(fld)
            allowed = list(getattr(rules.any, 'in')) if rules is not None and rules.HasField('any') else []
            if not allowed or any(url.rsplit('/', 1)[-1] in holders for url in allowed):
                found.append('%s.%s' % (name, fld.name))
    return found


def carriers_note(sizes):
    """The warning when an Any can hold a message that carries an Any itself, or ''."""

    if not sizes or not sizes.get('deeper'):
        return ''
    return ('Any.value (%d bytes) fits every message with one level of Any; %s can hold a message '
            'that carries an Any itself (no any.in, or any.in allows one), which fits only when '
            'encoded that small: set --any-value-size for deeper nesting'
            % (sizes['value'][0], ', '.join(sizes['deeper'])))


def exact_options(text, package, sizes):
    """The any.options text with every type_url / value max_size replaced by the exact ones,
    for the Any of ``package`` ("google.protobuf", or the prefixed "camera.google.protobuf")."""

    out = []
    for line in text.splitlines():
        if not line.lstrip().startswith('#'):
            for field in ('type_url', 'value'):
                match = re.match(ANY_FIELD_RE % field, line)
                if match:
                    line = (match.group(1) + match.group(2)).strip()
            if line.strip() and len(line.split()) < 2:     # only the name was left
                continue
        out.append(line)
    out.append('%s.Any.type_url max_size:%d' % (package, sizes['type_url'][0]))
    out.append('%s.Any.value max_size:%d' % (package, sizes['value'][0]))
    return ''.join(line + '\n' for line in out)


def project_any_options(unit):
    """Text of the first google/protobuf/any.options on the unit's include path ('' if none)."""

    for include in unit.includes:
        path = os.path.join(include, 'google', 'protobuf', 'any.options')
        if os.path.isfile(path):
            with open(path, encoding='utf-8') as handle:
                return handle.read()
    return ''


def write_exact_options_dir(unit, folder):
    """google/protobuf/any.options with the exact sizes under ``folder`` (put it first on the
    include path); False without Any."""

    sizes = exact_any_sizes(unit)
    if sizes is None:
        return False
    target = os.path.join(folder, 'google', 'protobuf', 'any.options')
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, 'w', encoding='utf-8', newline='\n') as handle:
        handle.write(exact_options(project_any_options(unit), 'google.protobuf', sizes))
    return True
