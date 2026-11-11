"""Generated C per protocol: runs nanopb + the validate plugin, merges each unit into
<unit>.pb.c/.h and <unit>_validate.c/.h, and reports PB_FIELD_32BIT needs (gen PROTOS_DIR).
"""

import concurrent.futures
import os
import re
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import env  # noqa: E402
from protos import (BackendError, INCLUDE_RE, OPTION_PROTOS, RUNTIME_FILES, Unit, VALIDATE_RUNTIME_FILES,  # noqa: E402
                    c_identifier, field_rules, is_option_proto, protocol_name, select_units, unit_entrypoints)


def generator_env():
    """Environment for protoc's plugins (see env.subprocess_env)."""

    return env.subprocess_env()


def run_generator(nanopb_root, unit, outdir, validate, filters=(), protocol=None, filter_name=None):
    common = ['-I' + p for p in unit.includes if os.path.isdir(p)]
    # e.g. -L'#include <NanoPB/%s>' (gen --include-prefix): reaches both plugins.
    common += getattr(unit, 'nanopb_opts', [])
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


def include_prefix_dir(prefix):
    """'NanoPB' from --include-prefix NanoPB (or NanoPB/), '' without one."""

    return (prefix or '').strip().strip('/\\')


def include_format_opts(prefix):
    """nanopb's -L option for `#include <PREFIX/pb.h>`, or nothing."""

    prefix = include_prefix_dir(prefix)
    return ['-L#include <%s/%%s>' % prefix] if prefix else []


def cmd_gen_c(args):
    validate = not args.no_validate

    # Descriptors and filter entrypoints first, one unit after the other: they
    # use protoc and protobuf in this process.
    jobs = []
    for name in select_units(args):
        unit = Unit(args.protos_root, name, args.include)
        unit.nanopb_opts = include_format_opts(getattr(args, 'include_prefix', None))
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
            # With an include prefix the runtime goes where <PREFIX/pb.h> finds it.
            prefix = include_prefix_dir(getattr(args, 'include_prefix', None))
            runtime_dir = os.path.join(outdir, prefix) if prefix else outdir
            if not os.path.isdir(runtime_dir):
                os.makedirs(runtime_dir)
            runtime = RUNTIME_FILES + (VALIDATE_RUNTIME_FILES if validate else ())
            for fname in runtime:
                src = os.path.join(env.RUNTIME_DIR if fname in VALIDATE_RUNTIME_FILES else args.nanopb_root, fname)
                if os.path.isfile(src):
                    shutil.copy(src, os.path.join(runtime_dir, fname))
                    files.append((prefix + '/' if prefix else '') + fname)
            if field_32bit:
                enable_field_32bit(os.path.join(runtime_dir, 'pb.h'))
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
