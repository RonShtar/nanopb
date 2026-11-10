#!/usr/bin/env python3
"""Engine behind `python -m nanopb_validate` (cli.py) and the Wireshark plugins.

Everything that touches .proto directories happens here: finding protocols
(units), merging their generated C, test packets and captures, the dissector
schema and installing the plugins. It reuses nanopb's generator read-only and
our validator, filter plugin and data generator. Use cli.py; these engine
commands are what its public commands map to:

  gen-c             <- gen PROTOS_DIR       merged <unit>.pb.c/.h + _validate.c/.h
  gen-packets       <- packets PROTOS_DIR   capture of PASSED and DROPPED packets
  install-studio    <- wireshark install    plugins + project copy, once
  install-dissector <- wireshark load       dissector + schema for a protos dir
  refresh-schema    <- wireshark refresh    rebuild the schema if protos changed
  units             <- wireshark units      protocols and their messages
  pick-units        <- wireshark pick       tick-box window to choose protocols
  gen-data, schema     (internal: sample messages, Lua schema)

A "protos root" is a directory whose subdirectories are *units* (protocols):
every subdirectory with .proto files, directly or in folders of its own.

All commands print a JSON result; the last line of output is always
``__EXIT__=<status>`` so that callers without access to the process exit
status (Lua 5.1 io.popen) can detect failures.
"""

from __future__ import print_function

import argparse
import concurrent.futures
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import env  # noqa: E402

# The Wireshark Lua plugins (validate/wireshark/).
TOOL_DIR = os.path.join(env.VALIDATE_DIR, 'wireshark')
# .options for google/protobuf/any.proto (static storage for Any).
DEFAULT_INCLUDE = os.path.join(env.PKG_DIR, 'wireshark_include')
DEFAULT_NANOPB_ROOT = env.NANOPB_ROOT

# Files that are only used for generator options and never generated.
OPTION_PROTOS = ('validate.proto', 'nanopb.proto')

RUNTIME_FILES = ('pb.h', 'pb_common.h', 'pb_common.c', 'pb_encode.h', 'pb_encode.c',
                 'pb_decode.h', 'pb_decode.c')
VALIDATE_RUNTIME_FILES = ('pb_validate.h', 'pb_validate.c', 'pb_filter_macros.h')

INCLUDE_RE = re.compile(r'^\s*#\s*include\s+"([^"]+)"\s*$')


class BackendError(Exception):
    pass


# ---------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------

def setup_nanopb(nanopb_root):
    """Use the nanopb checkout at ``nanopb_root`` (read-only) and build the _pb2 modules."""

    env.set_nanopb_root(nanopb_root)
    try:
        env.setup()
    except RuntimeError as exc:
        raise BackendError(str(exc))
    return env.GENERATOR_DIR


def is_option_proto(name):
    """True for a file that only defines generator options, in any folder."""

    return name == 'google/protobuf/descriptor.proto' or name.rsplit('/', 1)[-1] in OPTION_PROTOS


def find_units(protos_root):
    """Units of a protos directory: its subfolders that hold protos, directly
    or in folders of their own (protocol/enums/*.proto, protocol/messages/...).

    Vendored dependencies (google/, or a folder with only validate.proto or
    nanopb.proto) are not units. With no unit subfolder, a directory that
    holds .proto files itself is the one unit, named after the directory.
    """

    if not os.path.isdir(protos_root):
        raise BackendError('protos root %s is not a directory' % protos_root)
    units = []
    for name in sorted(os.listdir(protos_root)):
        path = os.path.join(protos_root, name)
        if not skipped_folder(name) and os.path.isdir(path) and all_unit_protos(path):
            units.append(name)
    if not units and unit_protos(protos_root):
        return [os.path.basename(os.path.abspath(protos_root))]
    return units


def skipped_folder(name):
    """Folders that never hold a unit's own protos: vendored google/, hidden ones."""

    return name == 'google' or name.startswith('.')


def unit_protos(unit_dir):
    """The unit's .proto files directly in ``unit_dir``."""

    return sorted(f for f in os.listdir(unit_dir)
                  if f.endswith('.proto') and os.path.isfile(os.path.join(unit_dir, f))
                  and not is_option_proto(f))


def unit_subfolders(unit_dir):
    """Every folder below ``unit_dir`` (absolute paths, parents first), without skipped ones."""

    result = []
    for root, dirs, _ in os.walk(unit_dir):
        dirs[:] = sorted(d for d in dirs if not skipped_folder(d))
        result += [os.path.join(root, d) for d in dirs]
    return result


def all_unit_protos(unit_dir):
    """The unit's .proto files in ``unit_dir`` and its subfolders, as '/'-separated
    paths relative to ``unit_dir``."""

    result = list(unit_protos(unit_dir))
    for folder in unit_subfolders(unit_dir):
        rel = os.path.relpath(folder, unit_dir).replace(os.sep, '/')
        result += [rel + '/' + f for f in unit_protos(folder)]
    return sorted(result)


def unit_folder(protos_root, name):
    """The folder of unit ``name``: a subfolder, or the root if it is the unit."""

    path = os.path.join(protos_root, name)
    return path if os.path.isdir(path) and all_unit_protos(path) else protos_root


def no_units_message(protos_root):
    return ('no .proto files found in %s or directly in its subfolders; '
            'enter the folder that holds your .proto files' % protos_root)


def select_units(args):
    all_units = find_units(args.protos_root)
    if not args.unit:
        if not all_units:
            raise BackendError(no_units_message(args.protos_root))
        return all_units
    wanted = [u.strip() for u in args.unit.split(',') if u.strip()]
    missing = [u for u in wanted if u not in all_units]
    if missing:
        raise BackendError('unknown unit(s) %s; available: %s'
                           % (', '.join(missing), ', '.join(all_units) or '(none)'))
    return wanted


def c_identifier(name):
    ident = re.sub(r'[^0-9A-Za-z_]', '_', name)
    if ident[:1].isdigit():
        ident = '_' + ident
    return ident


# ---------------------------------------------------------------------------
# Descriptors
# ---------------------------------------------------------------------------

def compile_descriptor_set(proto_names, include_paths):
    """Compile ``proto_names`` (virtual paths) to a FileDescriptorSet."""

    from proto._utils import invoke_protoc
    from google.protobuf import descriptor_pb2

    tmpdir = tempfile.mkdtemp(prefix='nanopb_ws_')
    try:
        out = os.path.join(tmpdir, 'set.pb')
        argv = ['protoc', '--include_imports', '--descriptor_set_out=' + out]
        argv += ['-I' + p for p in include_paths if os.path.isdir(p)]
        argv += list(proto_names)
        status = invoke_protoc(argv)
        if status != 0:
            raise BackendError('protoc failed (status %s) for %s' % (status, ' '.join(proto_names)))
        fds = descriptor_pb2.FileDescriptorSet()
        with open(out, 'rb') as handle:
            fds.ParseFromString(handle.read())
        return fds
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def nested_layout(unit_dir, parent, protos):
    """(include folders, protoc names) of a unit whose protos sit in subfolders.

    An import names a file relative to some folder: the unit folder
    ("enums/types.proto"), the protos root ("unit/enums/types.proto"), or
    a subfolder such as the importing file's own ("types.proto"). Every
    folder an import needs becomes an include path, and each proto gets the
    name its importers use, so protoc loads no file twice. Protos nobody
    imports are named relative to the unit folder.
    """

    def key(path):
        return os.path.normcase(os.path.abspath(path))

    paths = dict((p, key(os.path.join(unit_dir, p))) for p in protos)
    owner = dict((v, k) for k, v in paths.items())
    subfolders = unit_subfolders(unit_dir)
    imported_as, roots = {}, []
    for proto in protos:
        here = os.path.normpath(os.path.dirname(os.path.join(unit_dir, proto)))
        with open(os.path.join(unit_dir, proto), encoding='utf-8', errors='replace') as handle:
            imports = IMPORT_RE.findall(handle.read())
        for imp in imports:
            if imp.startswith('google/protobuf/'):
                continue
            for root in [here, unit_dir, parent] + subfolders:
                target = key(os.path.join(root, imp))
                if os.path.isfile(target):
                    break
            else:
                continue  # found through -I or the default include path, if at all
            if target in owner:
                previous = imported_as.setdefault(target, imp)
                if previous != imp:
                    raise BackendError('%s is imported both as "%s" and as "%s"; protoc needs one '
                                       'name per file, use the same import path everywhere'
                                       % (owner[target], previous, imp))
            if key(root) not in [key(r) for r in [unit_dir, parent] + roots]:
                roots.append(root)
    includes = [unit_dir] + roots + [parent]
    names = [imported_as.get(paths[p], p) for p in protos]
    # protoc finds a name in the first include folder that has it.
    for proto, name in zip(protos, names):
        found = next((key(os.path.join(r, name)) for r in includes
                      if os.path.isfile(os.path.join(r, name))), None)
        if found != paths[proto]:
            raise BackendError('import "%s" is ambiguous: %s and %s both match; rename one of them '
                               'or import it with its folder ("folder/%s")'
                               % (name, proto, os.path.relpath(found, unit_dir) if found else '?',
                                  os.path.basename(name)))
    return includes, names


class Unit(object):
    """One protos-root subdirectory, resolved to protoc virtual names."""

    def __init__(self, protos_root, name, extra_includes):
        self.name = name
        self.dir = unit_folder(protos_root, name)
        direct = unit_protos(self.dir)
        nested = all_unit_protos(self.dir)
        parent = os.path.dirname(self.dir)
        candidates = []
        if direct:
            candidates += [
                # Imports relative to the unit directory: import "foo.proto";
                (direct, [self.dir, parent], direct),
                # Imports relative to the protos root: import "unit/foo.proto";
                (direct, [parent, self.dir], [name + '/' + p for p in direct]),
            ]
        errors = []
        if len(nested) > len(direct):
            # Protos in subfolders (unit/enums/a.proto, unit/infra/messages/b.proto):
            # their import lines say which folders are include paths.
            try:
                candidates.append((nested,) + nested_layout(self.dir, parent, nested))
            except BackendError as exc:
                errors.append(str(exc))
        for protos, roots, names in candidates:
            includes = roots + list(extra_includes) + [DEFAULT_INCLUDE, env.VALIDATE_PROTO_DIR]
            try:
                self.fds = compile_descriptor_set(names, includes)
            except BackendError as exc:
                errors.append(str(exc))
                continue
            self.protos = protos
            self.includes = includes
            self.names = names
            break
        else:
            raise BackendError('could not compile unit %s:\n  %s' % (name, '\n  '.join(errors)))

    def generated_files(self):
        """Descriptor file names to generate, dependencies first."""

        return [f.name for f in self.fds.file if not is_option_proto(f.name)]

    def messages(self):
        result = []
        for fdesc in self.fds.file:
            if fdesc.name not in self.names:
                continue
            for msg in fdesc.message_type:
                result.append((fdesc.package + '.' if fdesc.package else '') + msg.name)
        return result


# ---------------------------------------------------------------------------
# gen-c
# ---------------------------------------------------------------------------

def field_rules(field):
    """The (validate.rules) option of a FieldDescriptorProto, or None."""

    from google.protobuf import descriptor_pb2
    from datagen import _load_validate_pb2

    validate_pb2 = _load_validate_pb2()
    # The descriptor set was parsed before the extension was known; parse the
    # options again so the extension is resolved.
    options = descriptor_pb2.FieldOptions.FromString(field.options.SerializeToString())
    if options.HasExtension(validate_pb2.rules):
        return options.Extensions[validate_pb2.rules]
    return None


def unit_entrypoints(unit, port_map):
    """Messages of the unit that get a packet filter, and where they came from.

    Port map entries are the protocol entrypoints the dissector uses. Without
    any for this unit, the roots are the unit's top-level messages that no
    other message of the unit uses as a field type or Any payload.
    """

    own = unit.messages()
    mapped = [msg for _, _, msg in parse_port_map(port_map, None) if msg in own]
    if mapped:
        return sorted(set(mapped), key=mapped.index), 'port map'

    referenced = set()

    def walk(msg):
        for fld in msg.field:
            if fld.type == 11:  # TYPE_MESSAGE
                referenced.add(fld.type_name.lstrip('.'))
            rules = field_rules(fld)
            if rules is not None and rules.HasField('any'):
                for item in getattr(rules.any, 'in'):
                    referenced.add(item.rsplit('/', 1)[-1].lstrip('.'))
        for nested in msg.nested_type:
            walk(nested)

    for fdesc in unit.fds.file:
        if fdesc.name in unit.names:
            for msg in fdesc.message_type:
                walk(msg)
    return [m for m in own if m not in referenced], 'auto'


def generator_env():
    """Environment for protoc's plugins (see env.subprocess_env)."""

    return env.subprocess_env()


def run_generator(nanopb_root, unit, outdir, validate, filters=(), protocol=None, filter_name=None):
    common = ['-I' + p for p in unit.includes if os.path.isdir(p)]
    # As imported: validate.proto, or validate/validate.proto in a subfolder.
    for name in sorted(set(OPTION_PROTOS) | set(f.name for f in unit.fds.file if is_option_proto(f.name))):
        common += ['-x', name]
    cmd = env.protoc_command() + ['-I' + p for p in unit.includes if os.path.isdir(p)]
    nanopb_opts = common + (['--protoc-insertion-points'] if validate else [])
    cmd += ['--nanopb_opt=' + o for o in nanopb_opts] + ['--nanopb_out=' + outdir]
    if validate:
        validate_opts = common + (['--filter=' + ';'.join(filters)] if filters else [])
        if protocol:
            validate_opts.append('--protocol-filter=' + protocol)
            if filter_name:
                validate_opts.append('--filter-name=' + filter_name)
        cmd += ['--nanopb-validate_opt=' + o for o in validate_opts] + ['--nanopb-validate_out=' + outdir]
    cmd += unit.generated_files()
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          universal_newlines=True, cwd=outdir, env=generator_env())
    if proc.returncode != 0:
        raise BackendError('generator failed for unit %s:\n%s' % (unit.name, proc.stdout))
    return proc.stdout


def plugin_error(text):
    """The plugin's own error lines from a failed generator run."""

    lines = text.splitlines()
    for i, line in enumerate(lines):
        if line.startswith('--nanopb-validate_out:'):
            return '\n'.join([line.split(':', 1)[1].strip()] + lines[i + 1:]).strip()
    return text.strip()


def predicted_mode(unit, entry):
    """Filter mode nanopb-validate will accept for ``entry``, decided up front.

    Dispatch needs exactly one Any field (with an any.in allow-list) or one
    oneof. Anything else is ambiguous, and the filter decodes and validates
    the entrypoint itself ('single'). Predicting this saves a generator run
    per entrypoint; run_generator_with_filters still falls back if wrong.
    """

    msg = None
    for fdesc in unit.fds.file:
        prefix = fdesc.package + '.' if fdesc.package else ''
        for candidate in fdesc.message_type:
            if prefix + candidate.name == entry:
                msg = candidate
    if msg is None:
        return 'auto'
    any_fields = [f for f in msg.field if f.type_name.lstrip('.') == 'google.protobuf.Any']
    oneofs = set(f.oneof_index for f in msg.field if f.HasField('oneof_index') and not f.proto3_optional)
    if len(any_fields) + len(oneofs) > 1 or any(f.label == 3 for f in any_fields):
        return 'single'
    if any_fields:
        rules = field_rules(any_fields[0])
        if rules is None or not rules.HasField('any') or not list(getattr(rules.any, 'in')):
            return 'single'
    return 'auto'


def run_generator_with_filters(nanopb_root, unit, outdir, validate, entries, protocol=None, filter_name=None):
    """Run the generator with as many of ``entries`` as the filter generator accepts.

    The filter generator refuses ambiguous or unsupported protocol shapes (two
    Any fields, an Any and a oneof, ...). Such an entrypoint is retried in
    ``single`` mode (decode and validate the entrypoint itself); if that fails
    too it is left out and reported. Validators are generated either way.
    Returns (log, {message: mode}, {message: error}).
    """

    def mode_of(spec):
        name, _, mode = spec.partition(':')
        return name, mode or 'auto'

    try:
        log = run_generator(nanopb_root, unit, outdir, validate, entries, protocol, filter_name)
        return log, dict(mode_of(e) for e in entries), {}
    except BackendError:
        if not entries:
            raise

    def accepted(spec):
        trial = tempfile.mkdtemp(prefix='nanopb_ws_try_')
        try:
            run_generator(nanopb_root, unit, trial, validate, [spec], protocol, filter_name)
            return None
        except BackendError as exc:
            return plugin_error(str(exc))
        finally:
            shutil.rmtree(trial, ignore_errors=True)

    modes, errors, specs = {}, {}, []
    for spec in entries:
        name, mode = mode_of(spec)
        error = accepted(spec)
        if error is None:
            modes[name] = mode
            specs.append(spec)
        elif mode != 'single' and accepted(name + ':single') is None:
            modes[name] = 'single'
            specs.append(name + ':single')
        else:
            errors[name] = error
    shutil.rmtree(outdir, ignore_errors=True)
    os.makedirs(outdir)
    return run_generator(nanopb_root, unit, outdir, validate, specs, protocol, filter_name), modes, errors


def strip_internal_includes(text, internal):
    lines = []
    for line in text.splitlines(True):
        match = INCLUDE_RE.match(line)
        if match and match.group(1) in internal:
            continue
        lines.append(line)
    return ''.join(lines)


def merge_unit(unit, gendir, outdir, validate, protocol=None):
    """Merge the unit's generated files into <unit>.pb.c/.h and <unit>_validate.c/.h.

    <unit>.pb.*: every .pb.c/.pb.h of the unit and its imports (types,
    descriptors, PB_BINDs) plus the packet filters, which nanopb-validate
    injects there. <unit>_validate.*: every validator. Includes between the
    merged files are replaced by one include of the right merged header.
    Returns (files written, header with the filter declarations, merged-from list).
    """

    bases = [os.path.splitext(n)[0] for n in unit.generated_files()]

    def existing(names):
        return [n for n in names if os.path.isfile(os.path.join(gendir, n))]

    protocol_files = ([protocol + '_filter.h'], [protocol + '_filter.c']) if protocol else ([], [])
    pb_headers = existing([b + '.pb.h' for b in bases] + protocol_files[0])
    pb_sources = existing([b + '.pb.c' for b in bases] + protocol_files[1])
    validate_headers = existing([b + '_validate.h' for b in bases]) if validate else []
    validate_sources = existing([b + '_validate.c' for b in bases]) if validate else []
    internal = set(pb_headers + validate_headers)

    ident = c_identifier(unit.name).upper()
    banner = ('/* Automatically generated by the nanopb validation tool (validate/ in the nanopb checkout).\n'
              ' * Unit "%s": %s\n'
              ' * Do not edit; regenerate from the .proto files instead. */\n'
              % (unit.name, ', '.join(unit.names)))

    def section(name):
        with open(os.path.join(gendir, name)) as handle:
            body = strip_internal_includes(handle.read(), internal)
        return '\n/* ---- %s ---- */\n%s' % (name, body)

    def write(name, text):
        from validator import tidy_c
        with open(os.path.join(outdir, name), 'w', newline='\n') as handle:
            handle.write(tidy_c(text))

    def write_header(name, guard, includes, parts):
        write(name, banner + '#ifndef %s\n#define %s\n' % (guard, guard)
              + ''.join('#include "%s"\n' % include for include in includes)
              + ''.join(section(part) for part in parts)
              + '\n#endif /* %s */\n' % guard)

    def write_source(name, includes, parts):
        write(name, banner + ''.join('#include "%s"\n' % include for include in includes)
              + ''.join(section(part) for part in parts))

    pb_h, pb_c = unit.name + '.pb.h', unit.name + '.pb.c'
    validate_h, validate_c = unit.name + '_validate.h', unit.name + '_validate.c'

    # The packet filters live in the .pb.c and call the validators.
    has_filters = False
    for name in pb_sources:
        with open(os.path.join(gendir, name)) as handle:
            has_filters = has_filters or '_filter_core(' in handle.read()

    write_header(pb_h, 'NANOPB_UNIT_%s_PB_H_INCLUDED' % ident, [], pb_headers)
    write_source(pb_c, [pb_h] + ([validate_h] if has_filters and validate_headers else []), pb_sources)
    files = [pb_h, pb_c]
    if validate_headers or validate_sources:
        write_header(validate_h, 'NANOPB_UNIT_%s_VALIDATE_H_INCLUDED' % ident, [pb_h], validate_headers)
        write_source(validate_c, [validate_h], validate_sources)
        files += [validate_h, validate_c]
    return files, pb_h, pb_headers + pb_sources + validate_headers + validate_sources


def protocol_name(unit):
    """C name of the unit's protocol filter, or None if the unit never uses Any."""

    if not any(f.name == 'google/protobuf/any.proto' for f in unit.fds.file):
        return None
    return c_identifier(unit.name)


def unit_root(unit):
    """The one message a unit's packets can be without an Any around them, or None."""

    roots, _ = unit_entrypoints(unit, None)
    return roots[0] if len(roots) == 1 else None


def protocol_messages(unit):
    """Messages a protocol accepts as Any payload: every message of the unit's
    compiled files (imports included) except map entries and google.protobuf.*,
    as nanopb-validate --protocol-filter does."""

    result = []

    def walk(prefix, msgs):
        for msg in msgs:
            fqn = prefix + msg.name
            if not msg.options.map_entry and not fqn.startswith('google.protobuf.'):
                result.append(fqn)
            walk(fqn + '.', msg.nested_type)

    for fdesc in unit.fds.file:
        if not is_option_proto(fdesc.name):
            walk(fdesc.package + '.' if fdesc.package else '', fdesc.message_type)
    return result


def validation_defines(unit):
    """Smallest PB_VALIDATE_MAX_PATH_DEPTH / _LENGTH that fit every validator of the unit.

    Each pb_validate_<msg>() keeps its own path stack relative to its message
    (nested messages report from their own validator), so a path is at most
    a field name plus an array index ("readings[65535]"), or with map.keys /
    map.values rules the entry's key or value too ("counts[65535].value").
    Smaller values shrink pb_violations_t and pb_validate_context_t; see
    docs/validation_performance.md.
    """

    longest, repeated, map_rules = 1, False, False

    def walk(msg):
        nonlocal longest, repeated, map_rules
        for fld in msg.field:
            longest = max(longest, len(fld.name))
            repeated = repeated or fld.label == 3
            rules_option = field_rules(fld) if fld.label == 3 else None
            if rules_option is not None and rules_option.HasField('map') and \
                    (rules_option.map.HasField('keys') or rules_option.map.HasField('values')):
                map_rules = True
        for nested in msg.nested_type:
            walk(nested)

    for fdesc in unit.fds.file:
        if not is_option_proto(fdesc.name):
            for msg in fdesc.message_type:
                walk(msg)
    index = len('[65535]') if repeated else 0  # pb_size_t is 16 bits without PB_FIELD_32BIT
    if map_rules:
        return {'PB_VALIDATE_MAX_PATH_DEPTH': 3,
                'PB_VALIDATE_MAX_PATH_LENGTH': longest + index + len('.value') + 1}
    return {'PB_VALIDATE_MAX_PATH_DEPTH': 2 if repeated else 1,
            'PB_VALIDATE_MAX_PATH_LENGTH': longest + index + 1}


def gen_c_summary(results):
    lines = []
    for r in results:
        lines.append('%s -> %s' % (r['unit'], r['dir']))
        lines.append('  ' + ', '.join(r['files']))
        if r.get('protocol_filter'):
            lines.append('  protocol filter (Any type_url = opcode, every message): %s/_tcp'
                         % r['protocol_filter'])
        elif r.get('protocol_filter_error'):
            lines.append('  no protocol filter: ' + r['protocol_filter_error'].splitlines()[0])
        if r['filters']:
            lines.append('  per-message filters: ' + ', '.join(f + '/_tcp' for f in r['filters']))
        for message, error in sorted(r.get('filter_errors', {}).items()):
            lines.append('  no filter for %s: %s' % (message, error.splitlines()[0]))
        if r.get('needs_field_32bit'):
            where = ('enabled in the copied pb.h' if r.get('field_32bit_enabled_in_pb_h') else
                     'compile EVERY file with -DPB_FIELD_32BIT, nanopb\'s pb_*.c too '
                     '(or uncomment it in pb.h, or pass --with-runtime)')
            lines.append('  needs PB_FIELD_32BIT (%s): %s; or lower max_size / max_count in the .options'
                         % ('; '.join(r['needs_field_32bit']), where))
        if r.get('recommended_defines'):
            lines.append('  smallest validation buffers: ' + ' '.join(
                '-D%s=%d' % kv for kv in sorted(r['recommended_defines'].items())))
    return '\n'.join(lines)


FIELD_32BIT_ERROR_RE = re.compile(r'^#error Enable PB_FIELD_32BIT to support messages exceeding 64kB in size: (.*)$',
                                  re.M)


def needs_field_32bit(unit, header_text):
    """Why the unit's C code only compiles with PB_FIELD_32BIT, or [] if it does not need it.

    Without it, field descriptors hold 16-bit tags, offsets, sizes and counts:
    a message struct of 64 kB or more (the generator's #error), or a tag
    above 65535, fails with FIELDINFO_DOES_NOT_FIT_width4/8_field<N>.
    """

    reasons = []
    big = []
    for match in FIELD_32BIT_ERROR_RE.finditer(header_text):
        big += [m.strip() for m in match.group(1).split(',') if m.strip()]
    if big:
        reasons.append('messages of 64 kB or more: ' + ', '.join(sorted(set(big))))
    tags = []

    def walk(prefix, msgs):
        for msg in msgs:
            tags.extend('%s%s.%s = %d' % (prefix, msg.name, f.name, f.number)
                        for f in msg.field if f.number > 65535)
            walk(prefix + msg.name + '.', msg.nested_type)

    for fdesc in unit.fds.file:
        if not is_option_proto(fdesc.name):
            walk(fdesc.package + '.' if fdesc.package else '', fdesc.message_type)
    if tags:
        reasons.append('field tags above 65535: ' + ', '.join(tags))
    return reasons


def enable_field_32bit(pb_h):
    """Turn on '#define PB_FIELD_32BIT 1' in a copied pb.h, for runtime and generated code alike."""

    with open(pb_h) as handle:
        text = handle.read()
    text = text.replace('/* #define PB_FIELD_32BIT 1 */', '#define PB_FIELD_32BIT 1', 1)
    with open(pb_h, 'w', newline='\n') as handle:
        handle.write(text)


def public_filter_name(template, protocol):
    """The protocol filter's C name: entry points <name>_udp / <name>_tcp."""

    name = (template or '{unit}_filter').replace('{unit}', protocol)
    if not re.match(r'^[A-Za-z_][A-Za-z0-9_]*$', name):
        raise BackendError('--filter-name %s gives "%s", which is not a C identifier' % (template, name))
    return name


def cmd_gen_c(args):
    validate = not args.no_validate

    # Descriptors and filter entrypoints first, one unit after the other: they
    # use protoc and protobuf in this process.
    jobs = []
    for name in select_units(args):
        unit = Unit(args.protos_root, name, args.include)
        entries, source_of_entries = [], None
        if validate and not args.no_filter:
            entries, source_of_entries = unit_entrypoints(unit, args.port_map)
        specs = [e + (':single' if predicted_mode(unit, e) == 'single' else '') for e in entries]
        protocol = protocol_name(unit) if validate and not args.no_filter else None
        public = public_filter_name(args.filter_name, protocol) if protocol else None
        jobs.append((name, unit, entries, source_of_entries, specs, protocol, public))

    def generate(job):
        # Only subprocesses and file I/O: safe to run for several units at once.
        name, unit, entries, source_of_entries, specs, protocol, public = job
        outdir = os.path.join(args.out, name)
        if not os.path.isdir(outdir):
            os.makedirs(outdir)
        gendir = tempfile.mkdtemp(prefix='nanopb_ws_gen_')
        protocol_error = None
        try:
            try:
                log, modes, filter_errors = run_generator_with_filters(args.nanopb_root, unit, gendir,
                                                                       validate, specs, protocol, public)
            except BackendError as exc:
                if not protocol:
                    raise
                # The protocol filter could not be generated (e.g. an Any with
                # callback storage): keep everything else.
                protocol_error, protocol = plugin_error(str(exc)), None
                shutil.rmtree(gendir, ignore_errors=True)
                os.makedirs(gendir)
                log, modes, filter_errors = run_generator_with_filters(args.nanopb_root, unit, gendir,
                                                                       validate, specs)
            files, header, parts = merge_unit(unit, gendir, outdir, validate, protocol)
        finally:
            shutil.rmtree(gendir, ignore_errors=True)
        with open(os.path.join(outdir, header)) as handle:
            header_text = handle.read()
        filters = re.findall(r'^int (\w+_udp)\(void \*ctx', header_text, re.M)
        protocol_filter = public + '_udp' if protocol and public + '_udp' in filters else None
        filters = [f for f in filters if f != protocol_filter]
        # The generator puts its '#error Enable PB_FIELD_32BIT' in the .pb.c.
        with open(os.path.join(outdir, name + '.pb.c')) as handle:
            field_32bit = needs_field_32bit(unit, header_text + handle.read())
        if args.with_runtime:
            runtime = RUNTIME_FILES + (VALIDATE_RUNTIME_FILES if validate else ())
            for fname in runtime:
                src = os.path.join(env.RUNTIME_DIR if fname in VALIDATE_RUNTIME_FILES else args.nanopb_root, fname)
                if os.path.isfile(src):
                    shutil.copy(src, os.path.join(outdir, fname))
                    files.append(fname)
            if field_32bit:
                enable_field_32bit(os.path.join(outdir, 'pb.h'))
        result = {'unit': name, 'dir': outdir, 'files': files, 'merged_from': parts,
                  'protocol_filter': protocol_filter, 'filters': filters, 'generator_log': log.strip()}
        if field_32bit:
            result['needs_field_32bit'] = field_32bit
            result['field_32bit_enabled_in_pb_h'] = bool(args.with_runtime)
        if protocol_error:
            result['protocol_filter_error'] = protocol_error
        elif not protocol_filter and validate and not args.no_filter:
            result['protocol_filter_error'] = "the protocol does not use google.protobuf.Any"

        if entries:
            result['filter_entrypoints'] = {'from': source_of_entries, 'modes': modes}
        if filter_errors:
            result['filter_errors'] = filter_errors
        return result

    # The generator run (protoc + two plugin processes) is most of the time.
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, min(len(jobs), os.cpu_count() or 1))) as pool:
        results = list(pool.map(generate, jobs))
    if validate:
        for result, job in zip(results, jobs):
            result['recommended_defines'] = validation_defines(job[1])
    return {'units': results, 'summary': gen_c_summary(results)}


# ---------------------------------------------------------------------------
# Captures
# ---------------------------------------------------------------------------

LOOPBACK = b'\x7f\x00\x00\x01'
SRC_PORT_BASE = 40000


def ip_checksum(data):
    if len(data) % 2:
        data += b'\x00'
    total = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def ethernet_frame(transport, port, payload, index):
    """Ethernet/IPv4/UDP or TCP frame from 127.0.0.1:<40000+index> to 127.0.0.1:<port>."""

    sport = SRC_PORT_BASE + index % 20000
    if transport == 'udp':
        proto = 17
        l4 = struct.pack('!HHHH', sport, port, 8 + len(payload), 0) + payload
    else:
        proto = 6
        header = struct.pack('!HHIIBBHHH', sport, port, 1000 + index, 1, 5 << 4, 0x18, 65535, 0, 0)
        pseudo = LOOPBACK + LOOPBACK + struct.pack('!BBH', 0, proto, len(header) + len(payload))
        csum = ip_checksum(pseudo + header + payload)
        l4 = header[:16] + struct.pack('!H', csum) + header[18:] + payload
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(l4), (index + 1) & 0xffff, 0x4000, 64, proto, 0,
                     LOOPBACK, LOOPBACK)
    ip = ip[:10] + struct.pack('!H', ip_checksum(ip)) + ip[12:]
    return b'\x00' * 12 + b'\x08\x00' + ip + l4


class Packet(object):
    """One captured packet: transport ('udp'/'tcp'), destination port, payload, optional comment."""

    def __init__(self, transport, port, payload, comment=None):
        self.transport = transport
        self.port = port
        self.payload = payload
        self.comment = comment


def _timestamps(count, start, step):
    start = time.time() if start is None else start
    for i in range(count):
        ts = start + i * step
        sec = int(ts)
        yield sec, int(round((ts - sec) * 1000000)) % 1000000


def write_pcap(path, packets, start=None, step=1.0):
    """Classic little-endian pcap (no comments)."""

    with open(path, 'wb') as handle:
        handle.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, (pkt, (sec, usec)) in enumerate(zip(packets, _timestamps(len(packets), start, step))):
            data = ethernet_frame(pkt.transport, pkt.port, pkt.payload, i)
            handle.write(struct.pack('<IIII', sec, usec, len(data), len(data)))
            handle.write(data)


def _pcapng_block(block_type, body):
    body += b'\x00' * (-len(body) % 4)
    length = 12 + len(body)
    return struct.pack('<II', block_type, length) + body + struct.pack('<I', length)


def _pcapng_option(code, value):
    return struct.pack('<HH', code, len(value)) + value + b'\x00' * (-len(value) % 4)


def write_pcapng(path, packets, start=None, step=0.001):
    """pcapng with one Ethernet interface; each packet's comment becomes opt_comment."""

    with open(path, 'wb') as handle:
        handle.write(_pcapng_block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1)))
        handle.write(_pcapng_block(1, struct.pack('<HHI', 1, 0, 65535)))
        for i, (pkt, (sec, usec)) in enumerate(zip(packets, _timestamps(len(packets), start, step))):
            data = ethernet_frame(pkt.transport, pkt.port, pkt.payload, i)
            ts = sec * 1000000 + usec
            body = struct.pack('<IIIII', 0, ts >> 32, ts & 0xffffffff, len(data), len(data))
            body += data + b'\x00' * (-len(data) % 4)
            if pkt.comment:
                body += _pcapng_option(1, pkt.comment.encode('utf-8')) + _pcapng_option(0, b'')
            handle.write(_pcapng_block(6, body))


def _frame_packet(data, comment):
    ip = data[14:]
    total = struct.unpack('!H', ip[2:4])[0]
    l4 = ip[(ip[0] & 0x0f) * 4:total]
    port = struct.unpack('!H', l4[2:4])[0]
    if ip[9] == 17:
        return Packet('udp', port, l4[8:], comment)
    return Packet('tcp', port, l4[(l4[12] >> 4) * 4:], comment)


def read_capture(path):
    """Packets of a capture written by write_pcap / write_pcapng."""

    with open(path, 'rb') as handle:
        data = handle.read()
    packets = []
    if struct.unpack('<I', data[:4])[0] == 0xa1b2c3d4:
        pos = 24
        while pos < len(data):
            incl = struct.unpack('<I', data[pos + 8:pos + 12])[0]
            packets.append(_frame_packet(data[pos + 16:pos + 16 + incl], None))
            pos += 16 + incl
        return packets
    pos = 0
    while pos < len(data):
        block_type, length = struct.unpack('<II', data[pos:pos + 8])
        if block_type == 6:
            incl = struct.unpack('<I', data[pos + 20:pos + 24])[0]
            frame = data[pos + 28:pos + 28 + incl]
            opt = pos + 28 + incl + (-incl % 4)
            comment = None
            while opt < pos + length - 4:
                code, olen = struct.unpack('<HH', data[opt:opt + 4])
                if code == 0:
                    break
                if code == 1:
                    comment = data[opt + 4:opt + 4 + olen].decode('utf-8')
                opt += 4 + olen + (-olen % 4)
            packets.append(_frame_packet(frame, comment))
        pos += length
    return packets


# ---------------------------------------------------------------------------
# gen-data
# ---------------------------------------------------------------------------

def c_array_header(ident, data):
    # The message's own C type is called `ident`, so the array gets a suffix.
    guard = 'NANOPB_DATA_%s_H_INCLUDED' % ident.upper()
    ident += '_data'
    rows = []
    for i in range(0, len(data), 12):
        rows.append('    ' + ', '.join('0x%02x' % b for b in data[i:i + 12]))
    return ('/* Generated sample data, %d bytes */\n'
            '#ifndef %s\n#define %s\n\n#include <stdint.h>\n\n'
            '#define %s_SIZE %du\n'
            'static const uint8_t %s[%d] = {\n%s\n};\n\n#endif\n'
            % (len(data), guard, guard, ident.upper(), len(data), ident,
               max(len(data), 1), ',\n'.join(rows) or '    0x00'))


def cmd_gen_data(args):
    from datagen import DataGenerator

    formats = set(f.strip() for f in args.formats.split(',') if f.strip())
    unknown = formats - {'bin', 'c', 'hex'}
    if unknown:
        raise BackendError('unknown format(s): %s (use bin,c,hex)' % ', '.join(sorted(unknown)))
    wanted = [m.strip() for m in (args.messages or '').split(',') if m.strip()]
    results = []
    errors = []
    for name in select_units(args):
        unit = Unit(args.protos_root, name, args.include)
        outdir = os.path.join(args.out, name, 'data')
        if not os.path.isdir(outdir):
            os.makedirs(outdir)
        produced = []
        gen = unit_data_generator(unit, DataGenerator)
        for msg in unit.messages():
            short = msg.split('.')[-1]
            if wanted and msg not in wanted and short not in wanted:
                continue
            for i in range(args.count):
                seed = None if args.seed is None else args.seed + i
                try:
                    if args.invalid:
                        data_dict = gen.generate_invalid(msg, violate_field=args.field,
                                                         violate_rule=args.rule, seed=seed)
                    else:
                        data_dict = gen.generate_valid(msg, seed=seed)
                    data = gen.encode_to_binary(msg, data_dict)
                except Exception as exc:
                    errors.append('%s: %s' % (msg, exc))
                    break
                ident = c_identifier(msg.replace('.', '_'))
                if args.count > 1:
                    ident += '_%d' % i
                if args.invalid:
                    ident += '_invalid'
                files = write_sample(outdir, ident, data, data_dict, formats)
                produced.append({'message': msg, 'size': len(data), 'files': files})
        if wanted and not produced:
            raise BackendError('nothing generated for %s in unit %s%s'
                               % (', '.join(wanted), name, ''.join('\n  ' + e for e in errors)))
        results.append({'unit': name, 'dir': outdir, 'messages': produced})
    if errors and not any(r['messages'] for r in results):
        raise BackendError('no data generated:\n  ' + '\n  '.join(errors))
    return {'units': results, 'errors': errors}


def write_sample(outdir, ident, data, data_dict, formats):
    files = []
    if 'bin' in formats:
        with open(os.path.join(outdir, ident + '.bin'), 'wb') as handle:
            handle.write(data)
        files.append(ident + '.bin')
    if 'c' in formats:
        with open(os.path.join(outdir, ident + '.h'), 'w', newline='\n') as handle:
            handle.write(c_array_header(ident, data))
        files.append(ident + '.h')
    if 'hex' in formats:
        with open(os.path.join(outdir, ident + '.hex'), 'w', newline='\n') as handle:
            handle.write(data.hex() + '\n')
        files.append(ident + '.hex')
    with open(os.path.join(outdir, ident + '.txt'), 'w', newline='\n') as handle:
        json.dump(data_dict, handle, indent=2, default=repr)
        handle.write('\n')
    files.append(ident + '.txt')
    return files


def unit_data_generator(unit, DataGenerator):
    """A DataGenerator that sees every message of the unit at once.

    DataGenerator loads one .proto and its imports; Any rules may name types
    from files that file doesn't import, so load a throwaway proto that
    imports the whole unit.
    """

    tmpdir = tempfile.mkdtemp(prefix='nanopb_ws_unit_')
    try:
        path = os.path.join(tmpdir, 'nanopb_ws_unit_all.proto')
        with open(path, 'w', newline='\n') as handle:
            handle.write('syntax = "proto3";\n')
            for name in unit.names:
                handle.write('import "%s";\n' % name)
        return DataGenerator(path, [p for p in unit.includes if os.path.isdir(p)])
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# ---------------------------------------------------------------------------
# schema / install
# ---------------------------------------------------------------------------

def lua_str(value):
    return '"' + value.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n') + '"'


# Field types whose values the dissector compares as 64-bit keys (True = signed).
INT64_TYPES = {3: True, 16: True, 18: True, 4: False, 6: False}  # INT64, SFIXED64, SINT64; UINT64, FIXED64

# Rule kinds nanopb-validate has no C emitter for: generating C code fails on
# them, so they never reject a packet. The dissector lists them as not checked.
UNSUPPORTED_KINDS = ('ONEOF_REQUIRED', 'NO_SPARSE')
UNSUPPORTED_OPTIONS = ('pattern', 'min_bytes', 'max_bytes')


def int64_key(value, signed):
    """Order-preserving 16-digit hex key of a 64-bit integer (signed: offset by 2^63)."""

    value = int(value)
    if signed:
        value += 1 << 63
    return '%016x' % (value & ((1 << 64) - 1))


VALUE_KINDS = ('GT', 'GTE', 'LT', 'LTE', 'EQ', 'IN', 'NOT_IN')


def rule_entry(rule_id, kind, params, field_type):
    entry = {'id': rule_id, 'kind': kind}
    # Only comparisons with the field's value use 64-bit keys, not counts or lengths.
    wide = field_type in INT64_TYPES and kind in VALUE_KINDS

    def scalar(value):
        if wide and isinstance(value, int) and not isinstance(value, bool):
            return int64_key(value, INT64_TYPES[field_type])
        return value

    if 'value' in params:
        entry['key' if wide and not isinstance(params['value'], bool) else 'v'] = scalar(params['value'])
    if 'values' in params:
        entry['keys' if wide else 'list'] = [scalar(v) for v in params['values']]
    if 'seconds' in params:
        entry['seconds'] = int(params['seconds'])
    if 'item_rules' in params:
        entry['items'] = [rule_entry(i.get('constraint_id', ''), i.get('rule'), i, field_type)
                          for i in params['item_rules']]
    if kind in UNSUPPORTED_KINDS:
        entry['kind'] = 'UNSUPPORTED'
    return entry


def field_rule_entries(field, rules_option=None):
    """The field's validate.proto rules as dissector rule entries.

    rules_option overrides the field's own (validate.rules), e.g. the
    map.keys / map.values rules applied to a map entry's key and value.
    map.keys / map.values themselves are not listed here: build_schema puts
    them on the fields of the map's *Entry message.
    """

    import validator as nanopb_validator

    if rules_option is None:
        rules_option = field_rules(field)
    if rules_option is None:
        return []
    option = type(rules_option)()
    option.CopyFrom(rules_option)
    entries = []
    for kind in ('string', 'bytes'):
        if option.HasField(kind):
            sub = getattr(option, kind)
            for name in UNSUPPORTED_OPTIONS:
                if name in sub.DESCRIPTOR.fields_by_name and sub.HasField(name):
                    entries.append({'id': '%s.%s' % (kind, name), 'kind': 'UNSUPPORTED'})
                    sub.ClearField(name)
    rules = nanopb_validator.FieldValidator(field, option).rules
    return [rule_entry(r.constraint_id, r.rule_type, r.params, field.type) for r in rules
            if r.rule_type != nanopb_validator.RULE_MAP_ENTRIES] + entries


def add_map_entry_rules(msg, messages):
    """Put a map field's map.keys / map.values rules on its *Entry message's
    key and value fields, so the dissector checks them on every entry (the
    paths, e.g. counts[1].key, match the C validator's)."""

    nested = dict((n.name, n) for n in msg.nested_type)
    for fld in msg.field:
        rules_option = field_rules(fld)
        if rules_option is None or not rules_option.HasField('map'):
            continue
        entry_desc = nested.get(fld.type_name.rsplit('.', 1)[-1])
        entry = messages.get(fld.type_name.lstrip('.'))
        if entry_desc is None or entry is None or not entry_desc.options.map_entry:
            continue
        entry_fields = entry['fields']
        for sub in entry_desc.field:
            part = {'key': 'keys', 'value': 'values'}.get(sub.name)
            if part and rules_option.map.HasField(part):
                rules = field_rule_entries(sub, getattr(rules_option.map, part))
                if rules:
                    entry_fields[sub.number].setdefault('rules', []).extend(rules)


def message_rule_entries(msg):
    """requires / mutex / at_least: no C enforcement, shown as not checked."""

    from google.protobuf import descriptor_pb2
    from datagen import _load_validate_pb2

    validate_pb2 = _load_validate_pb2()
    options = descriptor_pb2.MessageOptions.FromString(msg.options.SerializeToString())
    if not options.HasExtension(validate_pb2.message):
        return []
    rules = options.Extensions[validate_pb2.message]
    entries = [{'id': 'message.requires', 'kind': 'UNSUPPORTED', 'fields': [f]} for f in rules.requires]
    entries += [{'id': 'message.mutex', 'kind': 'UNSUPPORTED', 'fields': list(g.fields)} for g in rules.mutex]
    entries += [{'id': 'message.at_least', 'kind': 'UNSUPPORTED', 'fields': list(a.fields)}
                for a in rules.at_least]
    return entries


def field_presence(field, syntax):
    """How the C struct tracks presence: repeated, oneof, explicit (has_ flag), required, implicit."""

    if field.label == 3:
        return 'repeated'
    if field.HasField('oneof_index') and not field.proto3_optional:
        return 'oneof'
    if field.proto3_optional or field.type in (10, 11):
        return 'explicit'
    if syntax != 'proto3':
        return 'required' if field.label == 2 else 'explicit'
    return 'implicit'


def field_storage(info):
    """nanopb storage of a field: static, pointer, callback or ignore (from its .options)."""

    if info is None:
        return {'storage': 'static'}
    storage = info.storage
    if storage == 'static':
        # Without a size nanopb falls back to a callback, which pb_validate skips.
        if info.label == 3 and not info.max_count:
            storage = 'callback'
        elif info.type in (9, 12) and not info.max_size:
            storage = 'callback'
    result = {'storage': storage}
    if storage == 'static':
        if info.type in (9, 12) and info.max_size:
            result['max_size'] = info.max_size
            if info.type == 12 and info.fixed_length:
                result['fixed_length'] = True
        if info.label == 3 and info.max_count:
            result['max_count'] = info.max_count
    return result


def nanopb_field_info(units):
    """{(message, field number): ProtoFieldInfo} from the units' .options files."""

    from datagen import DataGenerator

    infos = {}
    for unit in units:
        try:
            gen = unit_data_generator(unit, DataGenerator)
        except Exception:  # sizes stay unknown; the rules still work
            continue
        for full_name, msg in gen.registry.messages_by_full_name.items():
            for info in msg.fields.values():
                infos.setdefault((full_name.lstrip('.'), info.number), info)
    return infos


def build_schema(fds_list, field_infos=None):
    messages = {}
    enums = {}
    field_infos = field_infos or {}

    def add_enum(prefix, enum):
        enums[prefix + enum.name] = dict((v.number, v.name) for v in enum.value)

    def add_message(prefix, msg, syntax):
        full = prefix + msg.name
        fields = {}
        for fld in msg.field:
            entry = {
                'name': fld.name,
                'type': fld.type,
                'label': fld.label,
                'type_name': fld.type_name.lstrip('.'),
                'presence': field_presence(fld, syntax),
            }
            if entry['presence'] == 'oneof':
                entry['oneof'] = msg.oneof_decl[fld.oneof_index].name
            entry.update(field_storage(field_infos.get((full, fld.number))))
            rules = field_rule_entries(fld)
            if rules:
                entry['rules'] = rules
            fields[fld.number] = entry
        messages[full] = {'fields': fields, 'map_entry': msg.options.map_entry}
        message_rules = message_rule_entries(msg)
        if message_rules:
            messages[full]['message_rules'] = message_rules
        for nested in msg.nested_type:
            add_message(full + '.', nested, syntax)
        add_map_entry_rules(msg, messages)
        for enum in msg.enum_type:
            add_enum(full + '.', enum)

    seen = set()
    for fds in fds_list:
        for fdesc in fds.file:
            if fdesc.name in seen or is_option_proto(fdesc.name):
                continue
            seen.add(fdesc.name)
            prefix = fdesc.package + '.' if fdesc.package else ''
            for msg in fdesc.message_type:
                add_message(prefix, msg, fdesc.syntax or 'proto2')
            for enum in fdesc.enum_type:
                add_enum(prefix, enum)
    return messages, enums


LUA_KEYWORDS = frozenset('and break do else elseif end false for function goto if in local nil not or '
                         'repeat return then true until while'.split())


def lua_bytes(data):
    """Lua string literal for text or bytes (decimal escapes work in Lua 5.1 - 5.4)."""

    if isinstance(data, str):
        data = data.encode('utf-8')
    out = []
    for b in bytearray(data):
        if b in (0x22, 0x5c):
            out.append('\\' + chr(b))
        elif 32 <= b < 127:
            out.append(chr(b))
        else:
            out.append('\\%03d' % b)
    return '"' + ''.join(out) + '"'


def lua_value(value):
    if value is None:
        return 'nil'
    if isinstance(value, bool):
        return 'true' if value else 'false'
    if isinstance(value, int):
        return str(value) if abs(value) < 1 << 53 else repr(float(value))
    if isinstance(value, float):
        if value != value:
            return '(0/0)'
        if value in (float('inf'), float('-inf')):
            return 'math.huge' if value > 0 else '-math.huge'
        return repr(value)
    if isinstance(value, (str, bytes)):
        return lua_bytes(value)
    if isinstance(value, (list, tuple)):
        return '{ ' + ', '.join(lua_value(v) for v in value) + ' }'
    if isinstance(value, dict):
        items = []
        for key in value:
            if value[key] is None:
                continue
            if isinstance(key, str) and re.match(r'^[A-Za-z_]\w*$', key) and key not in LUA_KEYWORDS:
                items.append('%s = %s' % (key, lua_value(value[key])))
            else:
                items.append('[%s] = %s' % (lua_value(key), lua_value(value[key])))
        return '{ ' + ', '.join(items) + ' }'
    raise TypeError('cannot render %r as Lua' % (value,))


FIELD_KEYS = ('name', 'type', 'label', 'type_name', 'presence', 'oneof', 'storage', 'max_size',
              'max_count', 'fixed_length', 'rules')


def render_messages_lua(messages):
    out = []
    for name in sorted(messages):
        msg = messages[name]
        rules = msg.get('message_rules')
        out.append('    [%s] = { map_entry = %s,%s fields = {\n'
                   % (lua_str(name), 'true' if msg['map_entry'] else 'false',
                      ' message_rules = %s,' % lua_value(rules) if rules else ''))
        for number in sorted(msg['fields']):
            f = msg['fields'][number]
            parts = ['%s = %s' % (k, lua_value(f[k])) for k in FIELD_KEYS if f.get(k) is not None]
            out.append('      [%d] = { %s },\n' % (number, ', '.join(parts)))
        out.append('    } },\n')
    return out


def render_enums_lua(enums):
    out = []
    for name in sorted(enums):
        values = ', '.join('[%d] = %s' % (n, lua_str(v)) for n, v in sorted(enums[name].items()))
        out.append('    [%s] = { %s },\n' % (lua_str(name), values))
    return out


def render_schema_lua(messages, enums, protocols=None, scoped=None, roots=None):
    """The schema as Lua. ``scoped``: {protocol: (messages, enums)} that it defines differently."""

    out = ['-- Generated by nanopb_validate; do not edit.\n',
           'return {\n  messages = {\n']
    out += render_messages_lua(messages)
    out.append('  },\n  protocols = {\n')
    for name in sorted(protocols or {}):
        out.append('    [%s] = %s,\n' % (lua_str(name), lua_value(protocols[name])))
    out.append('  },\n  enums = {\n')
    out += render_enums_lua(enums)
    out.append('  },\n')
    if roots:
        out.append('  roots = %s,\n' % lua_value(roots))
    if scoped:
        out.append('  scoped = {\n')
        for name in sorted(scoped):
            own_messages, own_enums = scoped[name]
            out.append('  [%s] = {\n  messages = {\n' % lua_str(name))
            out += render_messages_lua(own_messages)
            out.append('  },\n  enums = {\n')
            out += render_enums_lua(own_enums)
            out.append('  },\n  },\n')
        out.append('  },\n')
    out.append('}\n')
    return ''.join(out)


def merge_unit_schemas(unit_schemas):
    """Merge [(unit name, messages, enums)] into one view plus each unit's differences.

    Folders are separate protocols, but a name like pkg.Msg can be defined
    differently in two of them. The first definition goes in the shared view
    and each unit that differs keeps its own, so Decode As uses the right one.
    Returns (messages, enums, {unit: (messages, enums)}, sorted conflicting names).
    """

    messages, enums, scoped, conflicts = {}, {}, {}, set()
    for unit, own_messages, own_enums in unit_schemas:
        for shared, own, slot in ((messages, own_messages, 0), (enums, own_enums, 1)):
            for name, definition in own.items():
                if shared.setdefault(name, definition) != definition:
                    scoped.setdefault(unit, ({}, {}))[slot][name] = definition
                    conflicts.add(name)
    return messages, enums, scoped, sorted(conflicts)


def schema_text(protos_root, extra_includes):
    """(Lua schema text, messages, names defined differently by several units) for every unit."""

    units = [Unit(protos_root, name, extra_includes) for name in find_units(protos_root)]
    if not units:
        raise BackendError(no_units_message(protos_root))
    # Always know google.protobuf.Any, even if no unit imports it.
    any_fds = compile_descriptor_set(['google/protobuf/any.proto'], [DEFAULT_INCLUDE])
    messages, enums, scoped, conflicts = merge_unit_schemas(
        [(u.name,) + build_schema([u.fds], nanopb_field_info([u])) for u in units])
    any_messages, any_enums = build_schema([any_fds])
    for name, definition in any_messages.items():
        messages.setdefault(name, definition)
    for name, definition in any_enums.items():
        enums.setdefault(name, definition)
    # Every folder with messages of its own is a protocol in Wireshark (its
    # packets are an Any; the C protocol filter needs the unit to use Any).
    protocols = dict((u.name, m) for u, m in ((u, protocol_messages(u)) for u in units) if m)
    roots = dict((u.name, unit_root(u)) for u in units if u.name in protocols and unit_root(u))
    return render_schema_lua(messages, enums, protocols, scoped, roots), messages, conflicts


def write_if_changed(path, text):
    """Write ``text`` unless the file already holds it; True if written."""

    if os.path.isfile(path):
        with open(path, encoding='utf-8') as handle:
            if handle.read() == text:
                return False
    directory = os.path.dirname(os.path.abspath(path))
    if not os.path.isdir(directory):
        os.makedirs(directory)
    with open(path, 'w', encoding='utf-8', newline='\n') as handle:
        handle.write(text)
    return True


def write_schema(protos_root, extra_includes, path):
    text, messages, _ = schema_text(protos_root, extra_includes)
    write_if_changed(path, text)
    return messages


def cmd_schema(args):
    messages = write_schema(args.protos_root, args.include, args.out)
    return {'schema': os.path.abspath(args.out), 'messages': sorted(messages)}


def parse_port_map(text, messages):
    entries = []
    for item in re.split(r'[,;\s]+', text or ''):
        if not item:
            continue
        match = re.match(r'^(udp|tcp):(\d+)=([\w.]+)$', item, re.IGNORECASE)
        if not match:
            raise BackendError('bad port map entry %r (expected udp:5000=pkg.Message)' % item)
        msg = match.group(3)
        if messages is not None and msg not in messages:
            raise BackendError('port map message %s is not in the schema' % msg)
        entries.append((match.group(1).lower(), int(match.group(2)), msg))
    return entries


def prune_port_map(text, messages):
    """Split a saved port map into (entries still in ``messages``, stale entries).

    A saved map outlives the protos it was written for, so an entry for a
    message that is gone must not stop the protos now selected from loading.
    """

    kept, stale = [], []
    for proto, port, msg in parse_port_map(text, None):
        (kept if msg in messages else stale).append('%s:%d=%s' % (proto, port, msg))
    return ','.join(kept), stale


def protocols_of(schema):
    """Protocol names in a rendered schema."""

    block = schema.split('  protocols = {\n', 1)[-1].split('\n  },', 1)[0] if '  protocols = {' in schema else ''
    return re.findall(r'^    \["([^"]+)"\] = ', block, re.M)


def installed_protocol_ports(ports_path):
    """Protocol port entries of an installed ports.luadata."""

    try:
        with open(ports_path, encoding='utf-8') as handle:
            text = handle.read()
    except OSError:
        return []
    return [(t, int(port), name) for t, port, name in
            re.findall(r'\{ transport = "(udp|tcp)", port = (\d+), protocol = "([^"]+)" \}', text)]


def installed_port_map(ports_path):
    """The message entries of an installed ports.luadata as a port map string."""

    try:
        with open(ports_path, encoding='utf-8') as handle:
            text = handle.read()
    except OSError:
        return ''
    return ','.join('%s:%s=%s' % m for m in
                    re.findall(r'\{ transport = "(udp|tcp)", port = (\d+), message = "([^"]+)" \}', text))


def protos_fingerprint(protos_root, includes):
    """Cheap fingerprint of the protos: every .proto/.options path, size and
    mtime, plus this backend's own mtime (a tool update rebuilds the schema)."""

    import hashlib
    digest = hashlib.sha1()
    digest.update(str(int(os.stat(os.path.abspath(__file__)).st_mtime)).encode())
    for root in [protos_root] + list(includes or []):
        if not os.path.isdir(root):
            continue
        for dirpath, dirs, files in os.walk(root):
            dirs.sort()
            for name in sorted(files):
                if name.endswith(('.proto', '.options')):
                    path = os.path.join(dirpath, name)
                    st = os.stat(path)
                    digest.update(('%s|%d|%d\n' % (os.path.relpath(path, root), st.st_size,
                                                    int(st.st_mtime))).encode('utf-8'))
    return digest.hexdigest()


def install_schema(protos_root, includes, plugins, port_map, protocol_ports=None, drop_stale=False):
    """Install the dissector, its schema and port map into ``plugins``.

    ``protocol_ports`` of None keeps the protocol ports already installed.
    With ``drop_stale``, port map entries for messages not in these protos are
    removed instead of being an error (see prune_port_map).
    Only files whose content differs are written. Returns (result, changed, messages).
    """

    data_dir = os.path.join(plugins, 'nanopb')
    schema_path = os.path.join(data_dir, 'schema.luadata')
    fingerprint = protos_fingerprint(protos_root, includes)
    text, messages, conflicts = schema_text(protos_root, includes)
    changed = write_if_changed(schema_path, text)
    # refresh-schema compares against this to skip work when nothing changed.
    write_if_changed(os.path.join(data_dir, 'schema.fingerprint'), fingerprint + '\n')
    if protocol_ports is None:
        known = set(protocols_of(text))
        protocol_ports = [p for p in installed_protocol_ports(os.path.join(data_dir, 'ports.luadata'))
                          if p[2] in known]
    stale = []
    if drop_stale and port_map is not None:
        port_map, stale = prune_port_map(port_map, messages)
    ports = parse_port_map(port_map, messages)
    files = [schema_path]
    if port_map is not None or protocol_ports:
        lines = ['-- Default port map written by install-dissector.\nreturn {\n']
        for proto, port, msg in ports:
            lines.append('  { transport = %s, port = %d, message = %s },\n' % (lua_str(proto), port, lua_str(msg)))
        # Ports decoded with a protocol's own dissector (as with Decode As).
        for proto, port, name in protocol_ports:
            lines.append('  { transport = %s, port = %d, protocol = %s },\n' % (lua_str(proto), port, lua_str(name)))
        lines.append('}\n')
        ports_path = os.path.join(data_dir, 'ports.luadata')
        changed = write_if_changed(ports_path, ''.join(lines)) or changed
        files.append(ports_path)
    target = os.path.join(plugins, 'nanopb_any_dissector.lua')
    with open(tool_file('nanopb_any_dissector.lua'), encoding='utf-8') as handle:
        changed = write_if_changed(target, handle.read()) or changed
    files.insert(0, target)
    result = {'plugins_dir': plugins, 'files': files, 'messages': len(messages),
              'ports': ['%s:%d=%s' % p for p in ports] + ['%s:%d=<protocol %s>' % p for p in protocol_ports],
              'decode_as': [c_identifier(name).upper() for name in sorted(protocols_of(text))]}
    if conflicts:
        result['shared_names'] = conflicts
    if stale:
        result.update({'ports_pruned': True, 'port_map': port_map, 'stale_ports': stale})
    return result, changed, messages


def shared_names_note(names):
    return ('Defined differently by several protocols: %s. Each protocol uses its own definition; '
            'choose the protocol with Decode As, because plain NANOPB uses the first one.' % ', '.join(names))


def stale_ports_note(stale):
    return 'Removed from the port map, not in these protos: ' + ', '.join(stale)


def cmd_refresh_schema(args):
    """Rebuild the dissector schema if the protos changed since the last build.

    Run by nanopb_any_dissector.lua when Wireshark starts, with the protos
    directory saved in studio_config.luadata, so editing a .proto file needs
    no Load protos step. Exits quickly when nothing changed.
    """

    plugins = args.plugins_dir or default_plugins_dir()
    data_dir = os.path.join(plugins, 'nanopb')
    config = read_lua_config(os.path.join(data_dir, 'studio_config.luadata')) or {}
    protos_root = config.get('protos_root') or ''
    if not protos_root or not os.path.isdir(protos_root):
        return {'changed': False, 'skipped': 'no protos directory set',
                'summary': 'No protos directory set; nothing to refresh.'}
    includes = [i.strip() for i in (config.get('extra_includes') or '').split(';') if i.strip()]
    stored = ''
    try:
        with open(os.path.join(data_dir, 'schema.fingerprint')) as handle:
            stored = handle.read().strip()
    except (IOError, OSError):
        pass
    if stored == protos_fingerprint(protos_root, includes):
        return {'changed': False, 'summary': 'Schema is up to date with %s.' % protos_root}
    port_map = installed_port_map(os.path.join(data_dir, 'ports.luadata'))
    result, changed, _ = install_schema(protos_root, includes, plugins, port_map, drop_stale=True)
    result['changed'] = changed
    result['summary'] = 'Schema rebuilt from %s (%d messages).' % (protos_root, result['messages'])
    return result


def cmd_install_dissector(args):
    plugins = args.plugins_dir or default_plugins_dir()
    port_map = args.port_map
    saved = port_map is None
    if saved:
        port_map = installed_port_map(os.path.join(plugins, 'nanopb', 'ports.luadata'))
    result, changed, _ = install_schema(args.protos_root, args.include, plugins, port_map,
                                        drop_stale=saved or args.drop_stale_ports)
    result['changed'] = changed
    names = result['decode_as']
    lines = ['Loaded %d protocol(s) from %s:' % (len(names), args.protos_root)]
    lines += ['  %s' % n for n in names]
    lines += ['', 'Choose one:',
              '  for all NANOPB traffic: Edit > Preferences > Protocols > NANOPB > Protocol',
              '  per port: Analyze > Decode As > UDP port (or TCP port) > ' + (names[0] if names else '<FOLDER>'),
              '', '%d messages; ports: %s' % (result['messages'], ', '.join(result['ports']) or '(none)')]
    if result.get('stale_ports'):
        lines.append(stale_ports_note(result['stale_ports']))
    if result.get('shared_names'):
        lines.append(shared_names_note(result['shared_names']))
    result['summary'] = '\n'.join(lines)
    return result


# ---------------------------------------------------------------------------
# gen-packets
# ---------------------------------------------------------------------------

AUTO_PORT_BASE = 15000
DEFAULT_ANY_PORT = 15999
DEFAULT_PROTOCOL_PORT = 16000
ANY_URL_PREFIX = 'type.googleapis.com/'
ANY_MESSAGE = 'google.protobuf.Any'


def field_by_name(messages, msg, name):
    for fd in messages.get(msg, {}).get('fields', {}).values():
        if fd['name'] == name:
            return fd
    return None


def c_enforced(messages, msg, field, rule):
    """Would the C validator reject a message that breaks ``rule`` on ``field``?

    pb_validate checks `required` only on fields with a has_ flag, skips
    callback fields, and some rules have no C enforcement at all.
    """

    fd = field_by_name(messages, msg, field)
    if fd is None:
        return False
    if fd.get('storage') in ('callback', 'ignore'):
        return False
    if fd.get('storage') == 'pointer' and fd.get('presence') == 'repeated':
        return False
    if rule == 'required':
        return fd.get('presence') == 'explicit'
    base = rule.split('.', 1)[-1] if rule.startswith('items.') else rule
    unsupported = [r['id'].split('.')[-1] for r in fd.get('rules', []) if r['kind'] == 'UNSUPPORTED']
    return base not in unsupported and base not in ('pattern', 'min_bytes', 'max_bytes', 'no_sparse',
                                                    'oneof_required')


def any_wrap(type_name, payload):
    url = (ANY_URL_PREFIX + type_name).encode('utf-8')
    return (b'\x0a' + _varint(len(url)) + url + b'\x12' + _varint(len(payload)) + payload)


def _varint(n):
    out = bytearray()
    while True:
        b = n & 0x7f
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def write_packet_files(out, entries):
    """Every packet as <out>/<unit>/packets/<frame>_<Message>_<verdict>.h (C array) and .hex.

    Returns the packet directories. Old packet files are removed first, so the
    directory always matches the capture.
    """

    dirs = set()
    for entry in entries:
        directory = os.path.join(out, entry['unit'], 'packets')
        if directory not in dirs:
            if os.path.isdir(directory):
                for name in os.listdir(directory):
                    if name.endswith(('.h', '.hex')):
                        os.remove(os.path.join(directory, name))
            else:
                os.makedirs(directory)
            dirs.add(directory)
        ident = 'packet_%03d_%s_%s' % (entry['frame'], c_identifier(entry['message'].replace('.', '_')),
                                       entry['expect'])
        data = bytes.fromhex(entry['hex'])
        with open(os.path.join(directory, ident + '.h'), 'w', newline='\n') as handle:
            handle.write(c_array_header(ident, data))
        with open(os.path.join(directory, ident + '.hex'), 'w', newline='\n') as handle:
            handle.write(entry['hex'] + '\n')
        entry['files'] = [os.path.join(directory, ident + ext) for ext in ('.h', '.hex')]
    return dirs


def auto_port_map(units, base=AUTO_PORT_BASE):
    """One UDP port per unit root message (see unit_entrypoints)."""

    entries = []
    port = base
    for unit in units:
        roots, _ = unit_entrypoints(unit, '')
        for msg in roots:
            entries.append('udp:%d=%s' % (port, msg))
            port += 1
    return ','.join(entries)


def cmd_gen_packets(args):
    from datagen import DataGenerator, ValidationRuleNotViolatableError

    if args.valid < 0 or args.max_invalid < 0:
        raise BackendError('--valid and --max-invalid must not be negative')
    names = select_units(args)
    units = [Unit(args.protos_root, name, args.include) for name in names]
    protocol_mode = args.mode == 'protocol'
    # Protocol mode: every message of a unit, wrapped in an Any, on that
    # protocol's own port (decoded like Decode As -> nanopb_<unit>).
    # A unit that never uses Any and has one root message sends that message as it is.
    protocol_ports, protocol_of, direct = [], {}, {}
    if protocol_mode:
        for unit in units:
            if protocol_messages(unit):
                port = args.protocol_port + len(protocol_ports)
                protocol_ports.append(('udp', port, unit.name))
                protocol_of[unit.name] = port
                if protocol_name(unit) is None and unit_root(unit):
                    direct[unit.name] = unit_root(unit)
    port_map = args.port_map or ('' if protocol_mode else auto_port_map(units))
    # Map the Any port explicitly; left to the heuristic, other protocols'
    # heuristic dissectors can claim some of the packets first.
    if not protocol_mode and not any(port == args.any_port for _, port, _ in parse_port_map(port_map, None)):
        port_map = ','.join(p for p in (port_map, 'udp:%d=%s' % (args.any_port, ANY_MESSAGE)) if p)

    if args.no_install:
        _, messages, _ = schema_text(args.protos_root, args.include)
        installed, changed = None, False
        stale_ports = []
        if args.drop_stale_ports:
            port_map, stale_ports = prune_port_map(port_map, messages)
    else:
        plugins = args.plugins_dir or default_plugins_dir()
        installed, changed, messages = install_schema(args.protos_root, args.include, plugins, port_map,
                                                      protocol_ports, drop_stale=args.drop_stale_ports)
        stale_ports = installed.get('stale_ports', [])
        port_map = installed.get('port_map', port_map)
    roots = dict((msg, (proto, port)) for proto, port, msg in parse_port_map(port_map, messages)
                 if msg != ANY_MESSAGE)
    any_value = field_by_name(messages, ANY_MESSAGE, 'value') or {}
    any_url = field_by_name(messages, ANY_MESSAGE, 'type_url') or {}

    packets, entries, skipped, errors = [], [], [], []

    def add(unit, msg, data, expect, seed, violate=None):
        if protocol_mode:
            transport, port = 'udp', protocol_of[unit]
            wrapped = unit not in direct
            payload = any_wrap(msg, data) if wrapped else data
            if wrapped and ((any_value.get('max_size') and len(data) > any_value['max_size']) or
                            (any_url.get('max_size') and len(ANY_URL_PREFIX + msg) > any_url['max_size'])):
                return False
        elif msg in roots:
            transport, port = roots[msg]
            payload, wrapped = data, False
        else:
            transport, port = 'udp', args.any_port
            payload, wrapped = any_wrap(msg, data), True
            # A receiver with nanopb storage for Any cannot take more than that.
            too_long = (any_value.get('max_size') and len(data) > any_value['max_size']) or \
                       (any_url.get('max_size') and len(ANY_URL_PREFIX + msg) > any_url['max_size'])
            if too_long:
                return False
        comment = 'expect=%s msg=%s' % (expect.upper(), msg)
        if violate:
            comment += ' field=%s rule=%s' % (violate['field'], violate['rule'])
        comment += ' seed=%d' % seed
        packets.append(Packet(transport, port, payload, comment))
        entries.append({'frame': len(packets), 'unit': unit, 'message': msg, 'transport': transport,
                        'port': port, 'any_wrapped': wrapped, 'expect': expect, 'violate': violate,
                        'seed': seed, 'size': len(payload), 'hex': payload.hex()})
        return True

    for unit in units:
        if protocol_mode and unit.name not in protocol_of:
            skipped.append('%s: no messages of its own' % unit.name)
            continue
        try:
            gen = unit_data_generator(unit, DataGenerator)
        except Exception as exc:
            errors.append('%s: %s' % (unit.name, exc))
            continue
        for msg in ([direct[unit.name]] if unit.name in direct else unit.messages()):
            for i in range(args.valid):
                # Retry a few seeds if a sample does not fit an Any wrapper.
                for attempt in range(5):
                    seed = args.seed + i + 1000 * attempt
                    try:
                        data = gen.encode_to_binary(msg, gen.generate_valid(msg, seed=seed))
                    except Exception as exc:
                        errors.append('%s valid: %s' % (msg, exc))
                        break
                    if add(unit.name, msg, data, 'passed', seed):
                        break
                else:
                    skipped.append('%s valid #%d: larger than the Any.value storage' % (msg, i))
            count = 0
            for field, rule in gen.violatable_rules(msg):
                if count >= args.max_invalid:
                    skipped.append('%s: more rules than --max-invalid %d' % (msg, args.max_invalid))
                    break
                if not c_enforced(messages, msg, field, rule):
                    skipped.append('%s.%s %s: not enforced by the C validator' % (msg, field, rule))
                    continue
                seed = args.seed + count
                try:
                    data = gen.encode_to_binary(msg, gen.generate_invalid(msg, violate_field=field,
                                                                          violate_rule=rule, seed=seed))
                except (ValidationRuleNotViolatableError, ValueError) as exc:
                    skipped.append('%s.%s %s: %s' % (msg, field, rule, str(exc).splitlines()[0]))
                    continue
                if add(unit.name, msg, data, 'dropped', seed, {'field': field, 'rule': rule}):
                    count += 1
                else:
                    skipped.append('%s.%s %s: larger than the Any.value storage' % (msg, field, rule))

    if not packets:
        raise BackendError('no packets generated:\n  ' + '\n  '.join(errors + skipped))
    if not os.path.isdir(args.out):
        os.makedirs(args.out)
    base = os.path.join(args.out, 'nanopb_test_packets')
    capture = base + '.' + args.format
    start = time.time()
    if args.format == 'pcapng':
        write_pcapng(capture, packets, start=start)
    else:
        write_pcap(capture, packets, start=start, step=0.001)
    packet_files = write_packet_files(args.out, entries)
    passed = sum(1 for e in entries if e['expect'] == 'passed')
    dropped = len(entries) - passed
    if protocol_mode:
        ports = ['udp:%d=protocol %s (Decode As %s; %s)'
                 % (port, name, c_identifier(name).upper(),
                    'every packet is ' + direct[name] if name in direct else 'every message wrapped in an Any')
                 for _, port, name in protocol_ports]
    else:
        ports = ['%s:%d=%s' % (proto, port, msg) for msg, (proto, port) in sorted(roots.items(), key=lambda x: x[1])]
        ports.append('udp:%d=%s (every other message, wrapped in it)' % (args.any_port, ANY_MESSAGE))
    manifest = {'generated_at': start, 'capture': capture, 'port_map': port_map, 'any_port': args.any_port,
                'mode': args.mode, 'protocol_ports': ['%s:%d=%s' % p for p in protocol_ports],
                'packets': entries}
    with open(base + '.json', 'w', newline='\n') as handle:
        json.dump(manifest, handle, indent=1)
    lines = ['%d packets: %d expected PASSED, %d expected DROPPED' % (len(entries), passed, dropped),
             'Capture: ' + capture,
             'Each packet as C array (.h) and hex stream (.hex): ' + ', '.join(sorted(packet_files)),
             'Ports:'] + ['  ' + p for p in ports]
    lines += ['', 'frame  expect   message  [violated field / rule]']
    for e in entries:
        v = e['violate']
        lines.append('%5d  %-7s  %s%s' % (e['frame'], e['expect'].upper(), e['message'],
                                          '  [%s %s]' % (v['field'], v['rule']) if v else ''))
    if skipped:
        lines += ['', 'Not generated:'] + ['  ' + s for s in skipped]
    with open(base + '.txt', 'w', newline='\n') as handle:
        handle.write('\n'.join(lines) + '\n')
    summary = '\n'.join(lines[:4 + len(ports)])
    if skipped:
        summary += '\n%d rule(s) not generated, see %s.txt' % (len(skipped), base)
    if stale_ports:
        summary += '\n' + stale_ports_note(stale_ports)
    result = {'pcap': capture, 'manifest': base + '.json', 'summary_file': base + '.txt',
              'packet_dirs': sorted(packet_files), 'mode': args.mode,
              'protocol_ports': ['%s:%d=%s' % p for p in protocol_ports],
              'passed': passed, 'dropped': dropped, 'port_map': port_map, 'ports': ports,
              'skipped': skipped, 'errors': errors, 'schema_changed': changed, 'summary': summary}
    if installed:
        result['installed'] = installed
    if stale_ports:
        result['ports_pruned'] = True
    return result



def default_plugins_dir():
    """Personal Lua plugins folder (Help > About Wireshark > Folders)."""

    if os.name == 'nt':
        return os.path.join(os.environ.get('APPDATA', os.path.expanduser('~')), 'Wireshark', 'plugins')
    return os.path.join(os.path.expanduser('~'), '.local', 'lib', 'wireshark', 'plugins')


def tool_file(name):
    """A Lua plugin of this tool: <name>.lua in a checkout, <name>.lua.src in an installed copy."""

    for candidate in (name, name + '.src'):
        path = os.path.join(TOOL_DIR, candidate)
        if os.path.isfile(path):
            return path
    raise BackendError('%s not found in %s' % (name, TOOL_DIR))


def assert_no_lua(path):
    """Wireshark runs every .lua file below the plugins folder, so the copy may hold none."""

    for dirpath, _, filenames in os.walk(path):
        for name in filenames:
            if name.endswith('.lua'):
                raise BackendError('refusing to install %s: Wireshark would load it as a plugin'
                                   % os.path.join(dirpath, name))


def copy_project(src_root, dst):
    """Copy what the tool needs to ``dst`` with the checkout's layout: nanopb's
    runtime and generator, and validate/ (runtime, package, Lua as .src)."""

    if os.path.normcase(os.path.abspath(src_root)) == os.path.normcase(os.path.abspath(dst)):
        return  # running from the installed copy
    if os.path.isdir(dst):
        shutil.rmtree(dst)
    os.makedirs(dst)
    for name in RUNTIME_FILES + ('LICENSE.txt',):
        src = os.path.join(src_root, name)
        if os.path.isfile(src):
            shutil.copy(src, os.path.join(dst, name))
    ignore = shutil.ignore_patterns('__pycache__', '*.pyc', '*.lua')
    shutil.copytree(os.path.join(src_root, 'generator'), os.path.join(dst, 'generator'), ignore=ignore)
    src_validate = os.path.join(src_root, 'validate')
    dst_validate = os.path.join(dst, 'validate')
    shutil.copytree(os.path.join(src_validate, 'runtime'), os.path.join(dst_validate, 'runtime'))
    shutil.copytree(os.path.join(src_validate, 'nanopb_validate'), os.path.join(dst_validate, 'nanopb_validate'),
                    ignore=ignore)
    os.makedirs(os.path.join(dst_validate, 'wireshark'))
    for name in ('nanopb_any_dissector.lua', 'nanopb_studio.lua'):
        shutil.copy(os.path.join(src_validate, 'wireshark', name),
                    os.path.join(dst_validate, 'wireshark', name + '.src'))
    assert_no_lua(dst)


def git_commit(root):
    try:
        out = subprocess.run(['git', '-C', root, 'rev-parse', '--short', 'HEAD'], stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, universal_newlines=True)
        return out.stdout.strip() if out.returncode == 0 else None
    except OSError:
        return None


def check_environment():
    warnings = []
    try:
        import google.protobuf  # noqa: F401
    except ImportError:
        warnings.append('python package "protobuf" is missing for %s (pip install protobuf)' % sys.executable)
    try:
        import grpc_tools  # noqa: F401
    except ImportError:
        if not shutil.which('protoc'):
            warnings.append('neither grpcio-tools nor protoc found (pip install grpcio-tools)')
    return warnings


LUA_STRING_RE = re.compile(r'(\w+)\s*=\s*"((?:\\.|[^"\\])*)"')


def read_lua_config(path):
    """String keys of a studio_config.luadata file (written by us or by the studio's %q)."""

    if not os.path.isfile(path):
        return {}
    with open(path, encoding='utf-8') as handle:
        text = handle.read()
    unescape = {'n': '\n', '\n': '\n', 't': '\t'}
    return dict((key, re.sub(r'\\(.)', lambda m: unescape.get(m.group(1), m.group(1)), value, flags=re.S))
                for key, value in LUA_STRING_RE.findall(text))


def cmd_install_studio(args):
    plugins = args.plugins_dir or default_plugins_dir()
    data_dir = os.path.join(plugins, 'nanopb')
    project = os.path.join(data_dir, 'project')
    if not os.path.isdir(data_dir):
        os.makedirs(data_dir)
    copy_project(args.nanopb_root, project)
    files = []
    protos_root = os.path.abspath(args.protos_root) if args.protos_root else None
    for name in ('nanopb_studio.lua', 'nanopb_any_dissector.lua'):
        target = os.path.join(plugins, name)
        shutil.copy(tool_file(name), target)
        files.append(target)

    warnings = check_environment()
    info = {'source': os.path.abspath(args.nanopb_root), 'commit': git_commit(args.nanopb_root),
            'installed_at': time.strftime('%Y-%m-%d %H:%M:%S'), 'python': sys.executable, 'warnings': warnings}
    if os.path.isdir(project):
        with open(os.path.join(project, 'INSTALL_INFO.json'), 'w', newline='\n') as handle:
            json.dump(info, handle, indent=2)

    # Keep the user's last directories and port map; refresh where the tool lives.
    config_path = os.path.join(data_dir, 'studio_config.luadata')
    config = read_lua_config(config_path)
    config['python'] = sys.executable
    config['project'] = project
    config['nanopb_root'] = os.path.abspath(args.nanopb_root) if args.dev else ''
    loaded = None
    if protos_root:
        # One step: every menu starts from this directory, and Decode As already lists its protocols.
        loaded, _, _ = install_schema(protos_root, [], plugins, config.get('port_map', ''), drop_stale=True)
        config['protos_root'] = protos_root
        config['protos_root_fixed'] = '1'
        config['port_map'] = loaded.get('port_map', config.get('port_map', ''))
    keys = ['python', 'project', 'nanopb_root', 'protos_root', 'output_dir', 'extra_includes', 'port_map']
    keys += sorted(k for k in config if k not in keys)
    with open(config_path, 'w', newline='\n') as handle:
        handle.write('-- nanopb studio state (written by install-studio and the Tools > nanopb dialogs)\n'
                     'return {\n')
        for key in keys:
            handle.write('  %s = %s,\n' % (key, lua_str(config.get(key, ''))))
        handle.write('}\n')
    files += [project, config_path]
    result = {'plugins_dir': plugins, 'project': project, 'files': files, 'warnings': warnings,
              'mode': 'dev (uses %s)' % config['nanopb_root'] if args.dev else 'self-contained'}
    if loaded:
        result.update({'protos_root': protos_root, 'protocols': loaded['decode_as']})
    return result


IMPORT_RE = re.compile(r'^\s*import\s+(?:public\s+|weak\s+)?"([^"]+)"', re.M)


def merged_into(protos_root, units):
    """{unit: [units that import it]}: their merged .c/.h already contain it.

    Found by scanning import lines, so it needs no protoc run.
    """

    result = {}
    for name in units:
        folder = unit_folder(protos_root, name)
        for proto in all_unit_protos(folder):
            with open(os.path.join(folder, proto), encoding='utf-8', errors='replace') as handle:
                for path in IMPORT_RE.findall(handle.read()):
                    other = path.split('/', 1)[0]
                    if '/' in path and other != name and other in units and name not in result.get(other, []):
                        result.setdefault(other, []).append(name)
    return result


def cmd_units(args):
    if args.names_only:
        units = find_units(args.protos_root)
        return {'protos_root': os.path.abspath(args.protos_root), 'units': units,
                'merged_into': merged_into(args.protos_root, units)}
    result = []
    for name in find_units(args.protos_root):
        unit = Unit(args.protos_root, name, args.include)
        result.append({'unit': name, 'protos': unit.protos, 'messages': unit.messages(),
                       'dependencies': [n for n in unit.generated_files() if n not in unit.names]})
    return {'protos_root': os.path.abspath(args.protos_root), 'units': result}


def cmd_pick_units(args):
    """Tick boxes in a scrolling list; Wireshark's own windows cannot show them."""

    if os.environ.get('NANOPB_WS_NO_TK'):
        raise BackendError('tick box window disabled')
    try:
        import tkinter
        from tkinter import ttk
    except ImportError:
        raise BackendError('tkinter is not available')
    off = set(n for n in args.off.split(',') if n)
    root = tkinter.Tk()
    root.title(args.title)
    root.geometry('420x480')
    root.attributes('-topmost', True)
    chosen = []

    buttons = ttk.Frame(root)
    buttons.pack(side='bottom', fill='x', padx=6, pady=6)
    canvas = tkinter.Canvas(root, highlightthickness=0)
    bar = ttk.Scrollbar(root, orient='vertical', command=canvas.yview)
    canvas.configure(yscrollcommand=bar.set)
    bar.pack(side='right', fill='y')
    canvas.pack(side='left', fill='both', expand=True)
    inner = ttk.Frame(canvas)
    canvas.create_window((0, 0), window=inner, anchor='nw')
    inner.bind('<Configure>', lambda _: canvas.configure(scrollregion=canvas.bbox('all')))
    canvas.bind_all('<MouseWheel>', lambda e: canvas.yview_scroll(-e.delta // 120, 'units'))

    boxes = [(n, tkinter.BooleanVar(value=n not in off)) for n in args.names.split(',')]
    for name, var in boxes:
        ttk.Checkbutton(inner, text=name, variable=var).pack(anchor='w', padx=8, pady=2)

    def set_all(value):
        for _, var in boxes:
            var.set(value)

    def generate():
        chosen.extend(n for n, var in boxes if var.get())
        if chosen:
            root.destroy()

    for label, command, side in (('Select all', lambda: set_all(True), 'left'),
                                 ('Select none', lambda: set_all(False), 'left'),
                                 ('Cancel', root.destroy, 'right'),
                                 ('Generate', generate, 'right')):
        ttk.Button(buttons, text=label, command=command).pack(side=side, padx=2)
    root.mainloop()
    return {'units': chosen}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser():
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('--nanopb-root', default=DEFAULT_NANOPB_ROOT,
                        help='nanopb checkout to use (default: the one containing this script)')
    sub = parser.add_subparsers(dest='command')
    sub.required = True

    def protos_args(p, unit=False):
        p.add_argument('--protos-root', required=True,
                       help='directory whose subdirectories are units, or the one unit folder itself')
        p.add_argument('-I', '--include', action='append', default=[],
                       help='extra proto include path (repeatable)')
        if unit:
            p.add_argument('--unit', default='', help='comma-separated units (default: all)')

    p = sub.add_parser('units', help='list units and messages')
    protos_args(p)
    p.add_argument('--names-only', action='store_true', help='only list unit names (no proto compile)')
    p.set_defaults(func=cmd_units)

    p = sub.add_parser('gen-c', help='generate merged C code with validation')
    protos_args(p, unit=True)
    p.add_argument('--out', required=True, help='output directory (one subdirectory per unit)')
    p.add_argument('--with-runtime', action='store_true',
                   help='also copy the nanopb runtime (pb*.c/.h, pb_validate.*) next to the generated files')
    # Not copying is the default now; the old flag is still accepted.
    p.add_argument('--no-runtime', action='store_true', help=argparse.SUPPRESS)
    p.add_argument('--no-validate', action='store_true', help='skip validation code')
    p.add_argument('--port-map', default=None,
                   help='messages mapped here get a packet filter (default: unreferenced root messages)')
    p.add_argument('--no-filter', action='store_true', help='do not generate packet filters')
    p.add_argument('--filter-name', default='{unit}_filter',
                   help='name of the protocol filter; its entry points are <name>_udp and <name>_tcp '
                        '({unit} is the protocol folder, default: {unit}_filter)')
    p.set_defaults(func=cmd_gen_c)

    p = sub.add_parser('gen-data', help='generate encoded sample messages')
    protos_args(p, unit=True)
    p.add_argument('--out', required=True, help='output directory (<out>/<unit>/data)')
    p.add_argument('--messages', default='', help='comma-separated message names (default: all)')
    p.add_argument('--invalid', action='store_true', help='generate data that violates validation rules')
    p.add_argument('--field', action='append', default=None, help='field to violate (with --invalid)')
    p.add_argument('--rule', action='append', default=None, help='rule to violate (with --invalid)')
    p.add_argument('--seed', type=int, default=None, help='random seed (sample i uses seed+i)')
    p.add_argument('--count', type=int, default=1, help='samples per message')
    p.add_argument('--formats', default='bin,c,hex', help='any of bin,c,hex')
    p.set_defaults(func=cmd_gen_data)

    p = sub.add_parser('schema', help='write the dissector schema')
    protos_args(p)
    p.add_argument('--out', required=True, help='schema file to write (.luadata)')
    p.set_defaults(func=cmd_schema)

    p = sub.add_parser('refresh-schema', help='rebuild the dissector schema if the protos changed '
                                               '(run by the dissector at Wireshark start)')
    p.add_argument('--plugins-dir', default=None, help='Wireshark personal Lua plugins folder')
    p.set_defaults(func=cmd_refresh_schema)

    p = sub.add_parser('install-dissector', help='install dissector + schema into a plugins dir')
    protos_args(p)
    p.add_argument('--plugins-dir', default=None, help='default: personal Wireshark plugins folder')
    p.add_argument('--port-map', default=None,
                   help='e.g. "udp:5000=pkg.Envelope,tcp:7000=pkg.Cmd" (default: keep the installed one)')
    p.add_argument('--drop-stale-ports', action='store_true',
                   help='remove port map entries for messages not in these protos instead of failing')
    p.set_defaults(func=cmd_install_dissector)

    p = sub.add_parser('gen-packets', help='one capture with valid (PASSED) and invalid (DROPPED) packets')
    protos_args(p, unit=True)
    p.add_argument('--out', required=True, help='output directory for nanopb_test_packets.{pcapng,json,txt}')
    p.add_argument('--port-map', default='',
                   help='root messages sent on their own port (default: one UDP port per unit root, from %d)'
                   % AUTO_PORT_BASE)
    p.add_argument('--drop-stale-ports', action='store_true',
                   help='remove port map entries for messages not in these protos instead of failing')
    p.add_argument('--mode', choices=('ports', 'protocol'), default='ports',
                   help='ports: roots on their own port, others as Any on --any-port; protocol: every message '
                        'of each protocol (unit) wrapped in an Any on that protocol\'s port (--protocol-port)')
    p.add_argument('--protocol-port', type=int, default=DEFAULT_PROTOCOL_PORT,
                   help='first UDP port in protocol mode, one per protocol (default %d)' % DEFAULT_PROTOCOL_PORT)
    p.add_argument('--any-port', type=int, default=DEFAULT_ANY_PORT,
                   help='UDP port for other messages, wrapped in google.protobuf.Any (default %d)' % DEFAULT_ANY_PORT)
    p.add_argument('--valid', type=int, default=2, help='valid packets per message (default 2)')
    p.add_argument('--max-invalid', type=int, default=40, help='invalid packets per message at most (default 40)')
    p.add_argument('--seed', type=int, default=1, help='random seed (default 1)')
    p.add_argument('--format', choices=('pcapng', 'pcap'), default='pcapng')
    p.add_argument('--plugins-dir', default=None,
                   help='also install / refresh the dissector and schema here (default: personal plugins folder)')
    p.add_argument('--no-install', action='store_true', help='do not touch the Wireshark plugins folder')
    p.set_defaults(func=cmd_gen_packets)

    p = sub.add_parser('pick-units', help='choose units with tick boxes; prints the chosen ones')
    p.add_argument('--title', default='Choose protocols')
    p.add_argument('--names', required=True, help='comma-separated units')
    p.add_argument('--off', default='', help='comma-separated units that start unticked')
    p.set_defaults(func=cmd_pick_units)

    p = sub.add_parser('install-studio', help='install nanopb_studio.lua into a plugins dir')
    p.add_argument('--plugins-dir', default=None, help='default: personal Wireshark plugins folder')
    p.add_argument('--dev', action='store_true',
                   help='run this checkout instead of the copy (edits take effect without reinstalling)')
    p.add_argument('--protos-root', default=None,
                   help='directory with one subfolder per protocol: saved for every menu and loaded now')
    p.set_defaults(func=cmd_install_studio)
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    status = 1
    try:
        args.nanopb_root = os.path.abspath(args.nanopb_root)
        setup_nanopb(args.nanopb_root)
        if hasattr(args, 'include'):
            args.protos_root = os.path.abspath(args.protos_root)
            args.include = [os.path.abspath(p) for p in args.include]
        if getattr(args, 'count', 1) < 1:
            raise BackendError('--count must be at least 1')
        result = args.func(args)
        print(json.dumps(result, indent=2))
        status = 0
    except BackendError as exc:
        sys.stderr.write('error: %s\n' % exc)
    except Exception as exc:  # report anything else without a bare traceback in the GUI
        import traceback
        traceback.print_exc()
        sys.stderr.write('error: %s\n' % exc)
    sys.stderr.flush()
    sys.stdout.flush()
    print('__EXIT__=%d' % status)
    return status


if __name__ == '__main__':
    sys.exit(main())
