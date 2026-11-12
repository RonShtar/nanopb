"""Generated C per protocol: runs nanopb + the validate plugin, merges each unit into
<unit>.pb.c/.h and <unit>_validate.c/.h, and reports PB_FIELD_32BIT needs (gen PROTOS_DIR).
"""

import concurrent.futures
import os
import re
import shutil
import subprocess
import sys
import time
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import env  # noqa: E402
from protos import (BackendError, INCLUDE_RE, OPTION_PROTOS, RUNTIME_FILES, Unit, VALIDATE_RUNTIME_FILES,  # noqa: E402
                    c_identifier, field_rules, is_option_proto, protocol_name, select_units, unit_entrypoints)


def generator_env():
    """Environment for protoc's plugins (see env.subprocess_env)."""

    return env.subprocess_env()


def run_generator(nanopb_root, unit, outdir, validate, filters=(), protocol=None, filter_name=None):
    # First: e.g. -I<prefixing .options> (searched before the include paths) and
    # -L'#include <NanoPB/%s>' (gen --include-prefix); they reach both plugins.
    common = list(getattr(unit, 'nanopb_opts', []))
    common += ['-I' + p for p in unit.includes if os.path.isdir(p)]
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
        if filter_name and (protocol or len(filters) == 1):
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


DEFAULT_AUTHOR = 'Generated by nanopb validate'

#: `#include <...>` lines, hoisted to the top of a merged file (once each).
LIB_INCLUDE_RE = re.compile(r'^\s*#\s*include\s*<[^>]+>\s*$')
#: nanopb's per-file header version check, kept once per merged file.
VERSION_CHECK = ('#if PB_PROTO_HEADER_VERSION != 40\n'
                 '#error Regenerate this file with the current version of nanopb generator.\n'
                 '#endif\n')
VERSION_CHECK_RE = re.compile(r'^#if PB_PROTO_HEADER_VERSION != 40\n#error [^\n]*\n#endif\n?', re.M)


def file_header(name, brief, sources, author=None):
    """Doxygen block at the top of a generated file."""

    return ('/**\n'
            ' * @file %s\n'
            ' * @brief %s\n'
            ' * @date %s\n'
            ' * @author %s\n'
            ' *\n'
            ' * Generated from %s. Do not edit; regenerate from the .proto files.\n'
            ' */\n' % (name, brief, time.strftime('%Y-%m-%d'), author or DEFAULT_AUTHOR, ', '.join(sources)))


#: nanopb's alias for a prefixed name: '#define shared_Unit fleet_shared_Unit' and
#: '#define _shared_Unit_MIN _fleet_shared_Unit_MIN'.
ALIAS_RE = r'^#define (_*)(\w+) \1%s_\2[ \t]*$'


def alias_names(text, ident):
    """Old C names nanopb aliases to the protocol-prefixed ones: google_protobuf_Any, ..."""

    return [old for _, old in re.findall(ALIAS_RE % re.escape(ident), text, re.M)]


def scope_to_unit(text, ident, aliases):
    """Make a merged file safe to include next to other protocols' files.

    - inner header guards and nanopb's <FILE>_PB_H_MAX_SIZE macros get the
      protocol's name (two protocols both carry google/protobuf/any.pb.h's part);
    - nanopb's compatibility aliases for the prefixed imports are dropped and
      every use of an old name points at the prefixed one.
    """

    upper = ident.upper()
    own = re.compile(r'(^|_)%s(_|$)' % re.escape(upper))
    renames = {}
    for guard in re.findall(r'^#ifndef (\w+)\n#define \1\n', text, re.M):
        if not guard.startswith('NANOPB_UNIT_') and not own.search(guard):
            renames[guard] = ('PB_%s_%s' % (upper, guard[3:])) if guard.startswith('PB_') else upper + '_' + guard
    for macro in re.findall(r'^#define (\w+_PB_H_MAX_SIZE)\b', text, re.M):
        if not own.search(macro):
            renames[macro] = upper + '_' + macro
    for old, new in renames.items():
        text = re.sub(r'\b%s\b' % old, new, text)
    text = re.sub(ALIAS_RE % re.escape(ident) + r'\n?', '', text, flags=re.M)
    if aliases:
        names = '|'.join(re.escape(a) for a in sorted(set(aliases), key=len, reverse=True))
        text = re.sub(r'(?<![A-Za-z0-9_])(_*|pb_validate_)(%s)(?![A-Za-z0-9])' % names,
                      lambda m: m.group(1) + ident + '_' + m.group(2), text)
    return text


def merge_unit(unit, gendir, outdir, validate, protocol=None, author=None, public=None):
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
    filter_note = (' and packet filter %s_udp/_tcp' % public) if public else ''
    briefs = {
        '.pb.h': 'Protocol %s: message types, descriptors%s.' % (unit.name, filter_note),
        '.pb.c': 'Protocol %s: message descriptors%s.' % (unit.name, filter_note),
        '_validate.h': 'Protocol %s: validators, one pb_validate_<Message>() per message.' % unit.name,
        '_validate.c': 'Protocol %s: validator implementations.' % unit.name,
    }

    def banner(name):
        brief = next(text for suffix, text in briefs.items() if name.endswith(suffix))
        return file_header(name, brief, unit.names, author)

    def section(name):
        """A generated file's body: comments (except Doxygen), library #includes and
        nanopb's header-version check removed; write_*() put those once at the top."""

        from c_layout import strip_comments
        with open(os.path.join(gendir, name)) as handle:
            body = strip_comments(strip_internal_includes(handle.read(), internal))
        body, checks = VERSION_CHECK_RE.subn('', body)
        if checks:
            had_version_check.append(name)
        from c_layout import RUNTIME_CHECK
        if RUNTIME_CHECK in body:
            body = body.replace(RUNTIME_CHECK, '')
            had_runtime_check.append(name)
        kept = []
        for line in body.split('\n'):
            if LIB_INCLUDE_RE.match(line):
                if line.strip() not in lib_includes:
                    lib_includes.append(line.strip())
                continue
            kept.append(line)
        return '\n' + '\n'.join(kept)

    def top(parts):
        """Library includes (once) and whether nanopb's version check was in a section."""

        from c_layout import RUNTIME_CHECK
        bodies = ''.join(section(part) for part in parts)
        checks = (VERSION_CHECK if had_version_check else '') + (RUNTIME_CHECK if had_runtime_check else '')
        return ''.join(line + '\n' for line in lib_includes), bodies, checks

    def write(name, text):
        from c_layout import tidy_c
        with open(os.path.join(outdir, name), 'w', newline='\n') as handle:
            handle.write(tidy_c(scope_to_unit(text, c_identifier(unit.name), aliases)))

    # nanopb's aliases for the prefixed imports (#define google_protobuf_Any camera_google_protobuf_Any).
    aliases = []
    for name in pb_headers:
        with open(os.path.join(gendir, name)) as handle:
            aliases += alias_names(handle.read(), c_identifier(unit.name))

    def write_header(name, guard, includes, parts):
        del lib_includes[:], had_version_check[:], had_runtime_check[:]
        head, bodies, checks = top(parts)
        write(name, banner(name) + '#ifndef %s\n#define %s\n\n' % (guard, guard)
              + head + ''.join('#include "%s"\n' % include for include in includes)
              + checks + bodies + '\n#endif /* %s */\n' % guard)

    def write_source(name, includes, parts):
        del lib_includes[:], had_version_check[:], had_runtime_check[:]
        head, bodies, checks = top(parts)
        write(name, banner(name) + head + ''.join('#include "%s"\n' % include for include in includes)
              + checks + bodies)

    lib_includes = []
    had_version_check = []
    had_runtime_check = []

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


#: Output folder for the one runtime copy of a gen run with several protocols.
COMMON_UNIT = 'common'
#: Files an older version wrote to common/ (shared types); removed so they are not linked by mistake.
OLD_COMMON_FILES = ('common.pb.h', 'common.pb.c', 'common_validate.h', 'common_validate.c')


def renamed_option_lines(text, old_package, new_package):
    """The .options text plus, for every line naming the old package (google.protobuf.Any.value
    max_size:256), the same line under the new one: nanopb matches the renamed names."""

    old = (old_package + '.') if old_package else ''
    out = []
    for line in text.splitlines():
        out.append(line)
        parts = line.split(None, 1)
        if len(parts) == 2 and not parts[0].startswith('#') and '/' not in parts[0] and \
                parts[0].startswith(old) and not parts[0].startswith('*'):
            out.append(new_package + '.' + parts[0][len(old):] + ' ' + parts[1])
    return ''.join(line + '\n' for line in out)


def prefix_imports(unit, optdir):
    """Give every file the unit imports from outside its folder (google/protobuf/any.proto,
    a shared common.proto, ...) the unit's name as C prefix: camera_google_protobuf_Any.

    Each protocol then carries its own copy under its own names, so protocols
    generated separately (or with different .options for the same import) link
    into one program. It uses nanopb's own `package` file option, written into a
    .options file in ``optdir`` (searched first) together with the options that
    file already had. Returns {proto file: new C prefix}.
    """

    ident = c_identifier(unit.name)
    renamed = {}
    own = set(unit.names)
    for fdesc in unit.fds.file:
        if is_option_proto(fdesc.name) or fdesc.name in own:
            continue
        base = os.path.splitext(fdesc.name)[0]
        existing = ''
        for include in unit.includes:
            path = os.path.join(include, base + '.options')
            if os.path.isfile(path):
                with open(path, encoding='utf-8') as handle:
                    existing = handle.read().rstrip('\n') + '\n'
                break
        package = ident + ('.' + fdesc.package if fdesc.package else '')
        existing = renamed_option_lines(existing, fdesc.package, package)
        target = os.path.join(optdir, base + '.options')
        if not os.path.isdir(os.path.dirname(target)):
            os.makedirs(os.path.dirname(target))
        with open(target, 'w', encoding='utf-8', newline='\n') as handle:
            handle.write(existing + '%s package:"%s"\n' % (fdesc.name, package))
        renamed[fdesc.name] = package.replace('.', '_')
    return renamed


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


def gen_c_summary(results, common=None):
    lines = []
    if common:
        lines.append('%s -> %s' % (common['unit'], common['dir']))
        lines.append('  ' + ', '.join(common['files']))
        lines.append('  the nanopb runtime, once for every protocol (add -I%s)' % common['dir'])
    for r in results:
        lines.append('%s -> %s' % (r['unit'], r['dir']))
        lines.append('  ' + ', '.join(r['files']))
        if r.get('prefixed_imports'):
            lines.append('  imports under the protocol\'s prefix: ' + ', '.join(
                '%s -> %s_*' % kv for kv in sorted(r['prefixed_imports'].items())))
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
            where = ('enabled in the copied pb.h' + (' (in %s)' % (common['unit'] if common else 'common')
                                                     if r.get('field_32bit_in_common') else '')
                     if r.get('field_32bit_enabled_in_pb_h') else
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
    """The protocol's filter name: entry points <name>_udp / <name>_tcp (default: the folder name)."""

    name = (template or '{unit}').replace('{unit}', protocol)
    if not re.match(r'^[A-Za-z_][A-Za-z0-9_]*$', name):
        raise BackendError('--filter-name %s gives "%s", which is not a C identifier' % (template, name))
    return name


def include_prefix_dir(prefix):
    """'NanoPB' from --include-prefix NanoPB (or NanoPB/), '' without one."""

    return (prefix or '').strip().strip('/\\')


def include_format_opts(prefix):
    """nanopb's -L option for `#include <PREFIX/pb.h>`, or nothing."""

    prefix = include_prefix_dir(prefix)
    return ['-L#include <%s/%%s>' % prefix] if prefix else []


def cmd_gen_c(args):
    validate = not args.no_validate
    tempdirs = []

    # Descriptors and filter entrypoints first, one unit after the other: they
    # use protoc and protobuf in this process.
    jobs = []
    try:
        for name in select_units(args):
            unit = Unit(args.protos_root, name, args.include)
            optdir = tempfile.mkdtemp(prefix='nanopb_ws_opt_')
            tempdirs.append(optdir)
            renamed = prefix_imports(unit, optdir)
            # nanopb's -I is its .options search path: the prefixing options come first.
            unit.nanopb_opts = ['-I' + optdir] + include_format_opts(getattr(args, 'include_prefix', None))
            entries, source_of_entries = [], None
            protocol = protocol_name(unit) if validate and not args.no_filter else None
            # One filter per protocol, <name>_udp/_tcp (name = protocol folder or --filter-name):
            # with Any it takes any message of the protocol; without, the root message.
            if validate and not args.no_filter and not protocol:
                entries, source_of_entries = unit_entrypoints(unit, args.port_map)
            specs = [e + (':single' if predicted_mode(unit, e) == 'single' else '') for e in entries]
            public = public_filter_name(args.filter_name, c_identifier(name)) if (protocol or len(entries) == 1) else None
            jobs.append((name, unit, entries, source_of_entries, specs, protocol, public, renamed))
        return _gen_jobs(args, validate, jobs, tempdirs)
    finally:
        for path in tempdirs:
            shutil.rmtree(path, ignore_errors=True)


def _gen_jobs(args, validate, jobs, tempdirs):
    names = [job[0] for job in jobs]
    common = COMMON_UNIT
    while common in names:
        common = '_' + common
    prefix = include_prefix_dir(getattr(args, 'include_prefix', None))

    def copy_runtime(runtime_dir, files, field_32bit):
        # With an include prefix the runtime goes where <PREFIX/pb.h> finds it.
        runtime_dir = os.path.join(runtime_dir, prefix) if prefix else runtime_dir
        if not os.path.isdir(runtime_dir):
            os.makedirs(runtime_dir)
        for fname in RUNTIME_FILES + (VALIDATE_RUNTIME_FILES if validate else ()):
            src = os.path.join(env.RUNTIME_DIR if fname in VALIDATE_RUNTIME_FILES else args.nanopb_root, fname)
            if os.path.isfile(src):
                shutil.copy(src, os.path.join(runtime_dir, fname))
                files.append((prefix + '/' if prefix else '') + fname)
        if field_32bit:
            enable_field_32bit(os.path.join(runtime_dir, 'pb.h'))

    def run(job):
        # Only subprocesses and file I/O: safe to run for several units at once.
        name, unit, entries, source_of_entries, specs, protocol, public, _ = job
        gendir = tempfile.mkdtemp(prefix='nanopb_ws_gen_')
        tempdirs.append(gendir)
        protocol_error = None
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
        return gendir, protocol, protocol_error, log, modes, filter_errors

    def generate(job, ran, shared_runtime):
        name, unit, entries, source_of_entries, specs, _, public, renamed = job
        gendir, protocol, protocol_error, log, modes, filter_errors = ran
        outdir = os.path.join(args.out, name)
        if not os.path.isdir(outdir):
            os.makedirs(outdir)
        files, header, parts = merge_unit(unit, gendir, outdir, validate, protocol,
                                          getattr(args, 'author', None), public)
        with open(os.path.join(outdir, header)) as handle:
            header_text = handle.read()
        filters = re.findall(r'^int (\w+_udp)\(void \*ctx', header_text, re.M)
        protocol_filter = public + '_udp' if protocol and public + '_udp' in filters else None
        filters = [f for f in filters if f != protocol_filter]
        # The generator puts its '#error Enable PB_FIELD_32BIT' in the .pb.c.
        with open(os.path.join(outdir, name + '.pb.c')) as handle:
            field_32bit = needs_field_32bit(unit, header_text + handle.read())
        if args.with_runtime and not shared_runtime:
            copy_runtime(outdir, files, field_32bit)
        result = {'unit': name, 'dir': outdir, 'files': files, 'merged_from': parts, 'unit_object': unit,
                  'protocol_filter': protocol_filter, 'filters': filters, 'generator_log': log.strip()}
        if renamed:
            result['prefixed_imports'] = renamed
        if field_32bit:
            result['needs_field_32bit'] = field_32bit
            result['field_32bit_enabled_in_pb_h'] = bool(args.with_runtime)
            result['field_32bit_in_common'] = shared_runtime
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
        ran = list(pool.map(run, jobs))
    # Several protocols in one run: one runtime copy, so a program that links them all
    # has each runtime symbol once. Their types never clash: imports carry the protocol prefix.
    shared_runtime = bool(args.with_runtime and len(jobs) > 1)
    results = [generate(job, r, shared_runtime) for job, r in zip(jobs, ran)]
    common_result = None
    if shared_runtime:
        common_dir = os.path.join(args.out, common)
        if not os.path.isdir(common_dir):
            os.makedirs(common_dir)
        for old in OLD_COMMON_FILES:
            if os.path.isfile(os.path.join(common_dir, old)):
                os.remove(os.path.join(common_dir, old))
        files = []
        copy_runtime(common_dir, files, any(r.get('needs_field_32bit') for r in results))
        common_result = {'unit': common, 'dir': common_dir, 'files': files}
    if validate:
        for result in results:
            result['recommended_defines'] = validation_defines(result['unit_object'])
    for result in results:
        del result['unit_object']
    out = {'units': results, 'summary': gen_c_summary(results, common_result)}
    if common_result:
        out['common'] = common_result
    return out
