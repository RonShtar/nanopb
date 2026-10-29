#!/usr/bin/env python3
"""Backend for the nanopb Wireshark plugins.

The Lua plugins only collect input and display results; everything that
touches .proto files happens here, reusing the nanopb generator, the
validation plugin and the data generator from this repository.

A "protos root" is a directory whose subdirectories are *units*: every
subdirectory that contains .proto files is generated as one unit.

Subcommands (all print a JSON summary on success, errors go to stderr):

  units             list units and their messages
  gen-c             generate <unit>.pb.c/.h (all messages and the packet
                    filters) and <unit>_validate.c/.h (all validators) per unit
                    (--with-runtime also copies pb_*.c / pb_*.h)
  gen-data          generate sample encoded messages (.bin / C array / hex)
  gen-packets       one capture with valid (PASSED) and invalid (DROPPED)
                    packets of every message, plus a JSON manifest
  schema            write the Lua schema used by nanopb_any_dissector.lua
  install-dissector copy the dissector and its schema into a plugins dir
  install-studio    install the plugins and a copy of the generator, runtime
                    and this backend into a plugins dir

The last line of output is always ``__EXIT__=<status>`` so that callers
without access to the process exit status (Lua 5.1 io.popen) can detect
failures.
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

TOOL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND_DIR = os.path.join(TOOL_DIR, 'backend')
DEFAULT_INCLUDE = os.path.join(BACKEND_DIR, 'include')
DEFAULT_NANOPB_ROOT = os.path.dirname(os.path.dirname(TOOL_DIR))

# Files that are only used for generator options and never generated.
EXCLUDED_PROTOS = ('validate.proto', 'nanopb.proto', 'google/protobuf/descriptor.proto')

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
    """Make the generator modules of ``nanopb_root`` importable."""

    generator_dir = os.path.join(nanopb_root, 'generator')
    if not os.path.isfile(os.path.join(generator_dir, 'nanopb_generator.py')):
        raise BackendError('%s does not look like a nanopb checkout (no generator/nanopb_generator.py)'
                           % nanopb_root)
    if generator_dir not in sys.path:
        sys.path.insert(0, generator_dir)
    # A fresh checkout has no generator/proto/*_pb2.py yet. Build them the way
    # nanopb_generator does before anything imports them: otherwise the first
    # `import generator.proto.validate_pb2` (data generator, rule export) falls
    # through to grpc_tools' .proto importer, which fails on a duplicate
    # google/protobuf/descriptor.proto.
    import proto
    proto.load_nanopb_pb2()
    return generator_dir


def find_units(protos_root):
    if not os.path.isdir(protos_root):
        raise BackendError('protos root %s is not a directory' % protos_root)
    units = []
    for name in sorted(os.listdir(protos_root)):
        path = os.path.join(protos_root, name)
        if os.path.isdir(path) and unit_protos(path):
            units.append(name)
    return units


def unit_protos(unit_dir):
    return sorted(f for f in os.listdir(unit_dir)
                  if f.endswith('.proto') and os.path.isfile(os.path.join(unit_dir, f)))


def select_units(args):
    all_units = find_units(args.protos_root)
    if not args.unit:
        if not all_units:
            raise BackendError('no subdirectory of %s contains .proto files' % args.protos_root)
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


class Unit(object):
    """One protos-root subdirectory, resolved to protoc virtual names."""

    def __init__(self, protos_root, name, extra_includes):
        self.name = name
        self.dir = os.path.join(protos_root, name)
        self.protos = unit_protos(self.dir)
        candidates = [
            # Imports relative to the unit directory: import "foo.proto";
            ([self.dir, protos_root], self.protos),
            # Imports relative to the protos root: import "unit/foo.proto";
            ([protos_root, self.dir], [name + '/' + p for p in self.protos]),
        ]
        errors = []
        for roots, names in candidates:
            includes = roots + list(extra_includes) + [DEFAULT_INCLUDE]
            try:
                self.fds = compile_descriptor_set(names, includes)
            except BackendError as exc:
                errors.append(str(exc))
                continue
            self.includes = includes
            self.names = names
            break
        else:
            raise BackendError('could not compile unit %s:\n  %s' % (name, '\n  '.join(errors)))

    def generated_files(self):
        """Descriptor file names to generate, dependencies first."""

        return [f.name for f in self.fds.file if f.name not in EXCLUDED_PROTOS]

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
    from nanopb_data_generator import _load_validate_pb2

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


def run_generator(nanopb_root, unit, outdir, validate, filters=()):
    protoc = os.path.join(nanopb_root, 'generator', 'protoc')
    common = ['-I' + p for p in unit.includes if os.path.isdir(p)]
    common += ['-x', 'validate.proto', '-x', 'nanopb.proto']
    cmd = [sys.executable, protoc] + ['-I' + p for p in unit.includes if os.path.isdir(p)]
    nanopb_opts = common + (['--protoc-insertion-points'] if validate else [])
    cmd += ['--nanopb_opt=' + o for o in nanopb_opts] + ['--nanopb_out=' + outdir]
    if validate:
        validate_opts = common + (['--filter=' + ';'.join(filters)] if filters else [])
        cmd += ['--nanopb-validate_opt=' + o for o in validate_opts] + ['--nanopb-validate_out=' + outdir]
    cmd += unit.generated_files()
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          universal_newlines=True, cwd=outdir)
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


def run_generator_with_filters(nanopb_root, unit, outdir, validate, entries):
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
        log = run_generator(nanopb_root, unit, outdir, validate, entries)
        return log, dict(mode_of(e) for e in entries), {}
    except BackendError:
        if not entries:
            raise

    def accepted(spec):
        trial = tempfile.mkdtemp(prefix='nanopb_ws_try_')
        try:
            run_generator(nanopb_root, unit, trial, validate, [spec])
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
    return run_generator(nanopb_root, unit, outdir, validate, specs), modes, errors


def strip_internal_includes(text, internal):
    lines = []
    for line in text.splitlines(True):
        match = INCLUDE_RE.match(line)
        if match and match.group(1) in internal:
            continue
        lines.append(line)
    return ''.join(lines)


def merge_unit(unit, gendir, outdir, validate):
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

    pb_headers = existing([b + '.pb.h' for b in bases])
    pb_sources = existing([b + '.pb.c' for b in bases])
    validate_headers = existing([b + '_validate.h' for b in bases]) if validate else []
    validate_sources = existing([b + '_validate.c' for b in bases]) if validate else []
    internal = set(pb_headers + validate_headers)

    ident = c_identifier(unit.name).upper()
    banner = ('/* Automatically generated by tools/wireshark/backend/nanopb_wireshark.py.\n'
              ' * Unit "%s": %s\n'
              ' * Do not edit; regenerate from the .proto files instead. */\n'
              % (unit.name, ', '.join(unit.names)))

    def section(name):
        with open(os.path.join(gendir, name)) as handle:
            body = strip_internal_includes(handle.read(), internal)
        return '\n/* ---- %s ---- */\n%s' % (name, body)

    def write_header(name, guard, includes, parts):
        with open(os.path.join(outdir, name), 'w', newline='\n') as handle:
            handle.write(banner)
            handle.write('#ifndef %s\n#define %s\n' % (guard, guard))
            for include in includes:
                handle.write('#include "%s"\n' % include)
            for part in parts:
                handle.write(section(part))
            handle.write('\n#endif /* %s */\n' % guard)

    def write_source(name, includes, parts):
        with open(os.path.join(outdir, name), 'w', newline='\n') as handle:
            handle.write(banner)
            for include in includes:
                handle.write('#include "%s"\n' % include)
            for part in parts:
                handle.write(section(part))

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
    a field name plus an array index ("readings[65535]"). Smaller values
    shrink pb_violations_t and pb_validate_context_t; see
    docs/validation_performance.md.
    """

    longest, repeated = 1, False

    def walk(msg):
        nonlocal longest, repeated
        for fld in msg.field:
            longest = max(longest, len(fld.name))
            repeated = repeated or fld.label == 3
        for nested in msg.nested_type:
            walk(nested)

    for fdesc in unit.fds.file:
        if fdesc.name not in EXCLUDED_PROTOS:
            for msg in fdesc.message_type:
                walk(msg)
    index = len('[65535]') if repeated else 0  # pb_size_t is 16 bits without PB_FIELD_32BIT
    return {'PB_VALIDATE_MAX_PATH_DEPTH': 2 if repeated else 1,
            'PB_VALIDATE_MAX_PATH_LENGTH': longest + index + 1}


def gen_c_summary(results):
    lines = []
    for r in results:
        lines.append('%s -> %s' % (r['unit'], r['dir']))
        lines.append('  ' + ', '.join(r['files']))
        if r['filters']:
            lines.append('  packet filters: ' + ', '.join(f + '/_tcp' for f in r['filters']))
        for message, error in sorted(r.get('filter_errors', {}).items()):
            lines.append('  no filter for %s: %s' % (message, error.splitlines()[0]))
        if r.get('recommended_defines'):
            lines.append('  smallest validation buffers: ' + ' '.join(
                '-D%s=%d' % kv for kv in sorted(r['recommended_defines'].items())))
    return '\n'.join(lines)


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
        jobs.append((name, unit, entries, source_of_entries, specs))

    def generate(job):
        # Only subprocesses and file I/O: safe to run for several units at once.
        name, unit, entries, source_of_entries, specs = job
        outdir = os.path.join(args.out, name)
        if not os.path.isdir(outdir):
            os.makedirs(outdir)
        gendir = tempfile.mkdtemp(prefix='nanopb_ws_gen_')
        try:
            log, modes, filter_errors = run_generator_with_filters(args.nanopb_root, unit, gendir,
                                                                   validate, specs)
            files, header, parts = merge_unit(unit, gendir, outdir, validate)
        finally:
            shutil.rmtree(gendir, ignore_errors=True)
        with open(os.path.join(outdir, header)) as handle:
            filters = re.findall(r'^int (\w+_filter_udp)\(', handle.read(), re.M)
        if args.with_runtime:
            runtime = RUNTIME_FILES + (VALIDATE_RUNTIME_FILES if validate else ())
            for fname in runtime:
                src = os.path.join(args.nanopb_root, fname)
                if os.path.isfile(src):
                    shutil.copy(src, os.path.join(outdir, fname))
                    files.append(fname)
        result = {'unit': name, 'dir': outdir, 'files': files, 'merged_from': parts,
                  'filters': filters, 'generator_log': log.strip()}
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
    from nanopb_data_generator import DataGenerator

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


def field_rule_entries(field):
    """The field's validate.proto rules as dissector rule entries."""

    import nanopb_validator

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
    return [rule_entry(r.constraint_id, r.rule_type, r.params, field.type) for r in rules] + entries


def message_rule_entries(msg):
    """requires / mutex / at_least: no C enforcement, shown as not checked."""

    from google.protobuf import descriptor_pb2
    from nanopb_data_generator import _load_validate_pb2

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

    from nanopb_data_generator import DataGenerator

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
        for enum in msg.enum_type:
            add_enum(full + '.', enum)

    seen = set()
    for fds in fds_list:
        for fdesc in fds.file:
            if fdesc.name in seen or fdesc.name in EXCLUDED_PROTOS:
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


def render_schema_lua(messages, enums):
    out = ['-- Generated by tools/wireshark/backend/nanopb_wireshark.py; do not edit.\n',
           'return {\n  messages = {\n']
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
    out.append('  },\n  enums = {\n')
    for name in sorted(enums):
        values = ', '.join('[%d] = %s' % (n, lua_str(v)) for n, v in sorted(enums[name].items()))
        out.append('    [%s] = { %s },\n' % (lua_str(name), values))
    out.append('  },\n}\n')
    return ''.join(out)


def schema_text(protos_root, extra_includes):
    """(Lua schema text, messages) for every unit of the protos root."""

    units = [Unit(protos_root, name, extra_includes) for name in find_units(protos_root)]
    if not units:
        raise BackendError('no subdirectory of %s contains .proto files' % protos_root)
    # Always know google.protobuf.Any, even if no unit imports it.
    any_fds = compile_descriptor_set(['google/protobuf/any.proto'], [DEFAULT_INCLUDE])
    messages, enums = build_schema([u.fds for u in units] + [any_fds], nanopb_field_info(units))
    return render_schema_lua(messages, enums), messages


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
    text, messages = schema_text(protos_root, extra_includes)
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


def install_schema(protos_root, includes, plugins, port_map):
    """Install the dissector, its schema and port map into ``plugins``.

    Only files whose content differs are written. Returns (result, changed, messages).
    """

    data_dir = os.path.join(plugins, 'nanopb')
    schema_path = os.path.join(data_dir, 'schema.luadata')
    text, messages = schema_text(protos_root, includes)
    changed = write_if_changed(schema_path, text)
    ports = parse_port_map(port_map, messages)
    files = [schema_path]
    if port_map is not None:
        lines = ['-- Default port map written by install-dissector.\nreturn {\n']
        for proto, port, msg in ports:
            lines.append('  { transport = %s, port = %d, message = %s },\n' % (lua_str(proto), port, lua_str(msg)))
        lines.append('}\n')
        ports_path = os.path.join(data_dir, 'ports.luadata')
        changed = write_if_changed(ports_path, ''.join(lines)) or changed
        files.append(ports_path)
    target = os.path.join(plugins, 'nanopb_any_dissector.lua')
    with open(tool_file('nanopb_any_dissector.lua'), encoding='utf-8') as handle:
        changed = write_if_changed(target, handle.read()) or changed
    files.insert(0, target)
    result = {'plugins_dir': plugins, 'files': files, 'messages': len(messages),
              'ports': ['%s:%d=%s' % p for p in ports]}
    return result, changed, messages


def cmd_install_dissector(args):
    plugins = args.plugins_dir or default_plugins_dir()
    result, changed, _ = install_schema(args.protos_root, args.include, plugins, args.port_map)
    result['changed'] = changed
    return result


# ---------------------------------------------------------------------------
# gen-packets
# ---------------------------------------------------------------------------

AUTO_PORT_BASE = 15000
DEFAULT_ANY_PORT = 15999
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
    from nanopb_data_generator import DataGenerator, ValidationRuleNotViolatableError

    if args.valid < 0 or args.max_invalid < 0:
        raise BackendError('--valid and --max-invalid must not be negative')
    names = select_units(args)
    units = [Unit(args.protos_root, name, args.include) for name in names]
    port_map = args.port_map or auto_port_map(units)
    # Map the Any port explicitly; left to the heuristic, other protocols'
    # heuristic dissectors can claim some of the packets first.
    if not any(port == args.any_port for _, port, _ in parse_port_map(port_map, None)):
        port_map = ','.join(p for p in (port_map, 'udp:%d=%s' % (args.any_port, ANY_MESSAGE)) if p)

    if args.no_install:
        _, messages = schema_text(args.protos_root, args.include)
        installed, changed = None, False
    else:
        plugins = args.plugins_dir or default_plugins_dir()
        installed, changed, messages = install_schema(args.protos_root, args.include, plugins, port_map)
    roots = dict((msg, (proto, port)) for proto, port, msg in parse_port_map(port_map, messages)
                 if msg != ANY_MESSAGE)
    any_value = field_by_name(messages, ANY_MESSAGE, 'value') or {}
    any_url = field_by_name(messages, ANY_MESSAGE, 'type_url') or {}

    packets, entries, skipped, errors = [], [], [], []

    def add(unit, msg, data, expect, seed, violate=None):
        if msg in roots:
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
        try:
            gen = unit_data_generator(unit, DataGenerator)
        except Exception as exc:
            errors.append('%s: %s' % (unit.name, exc))
            continue
        for msg in unit.messages():
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
    passed = sum(1 for e in entries if e['expect'] == 'passed')
    dropped = len(entries) - passed
    ports = ['%s:%d=%s' % (proto, port, msg) for msg, (proto, port) in sorted(roots.items(), key=lambda x: x[1])]
    ports.append('udp:%d=%s (every other message, wrapped in it)' % (args.any_port, ANY_MESSAGE))
    manifest = {'generated_at': start, 'capture': capture, 'port_map': port_map, 'any_port': args.any_port,
                'packets': entries}
    with open(base + '.json', 'w', newline='\n') as handle:
        json.dump(manifest, handle, indent=1)
    lines = ['%d packets: %d expected PASSED, %d expected DROPPED' % (len(entries), passed, dropped),
             'Capture: ' + capture, 'Ports:'] + ['  ' + p for p in ports]
    lines += ['', 'frame  expect   message  [violated field / rule]']
    for e in entries:
        v = e['violate']
        lines.append('%5d  %-7s  %s%s' % (e['frame'], e['expect'].upper(), e['message'],
                                          '  [%s %s]' % (v['field'], v['rule']) if v else ''))
    if skipped:
        lines += ['', 'Not generated:'] + ['  ' + s for s in skipped]
    with open(base + '.txt', 'w', newline='\n') as handle:
        handle.write('\n'.join(lines) + '\n')
    summary = '\n'.join(lines[:3 + len(ports)])
    if skipped:
        summary += '\n%d rule(s) not generated, see %s.txt' % (len(skipped), base)
    result = {'pcap': capture, 'manifest': base + '.json', 'summary_file': base + '.txt',
              'passed': passed, 'dropped': dropped, 'port_map': port_map, 'ports': ports,
              'skipped': skipped, 'errors': errors, 'schema_changed': changed, 'summary': summary}
    if installed:
        result['installed'] = installed
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
    """Copy what the backend needs (generator, runtime, backend) to ``dst``, keeping the repo layout."""

    if os.path.normcase(os.path.abspath(src_root)) == os.path.normcase(os.path.abspath(dst)):
        return  # running from the installed copy
    if os.path.isdir(dst):
        shutil.rmtree(dst)
    os.makedirs(dst)
    for name in RUNTIME_FILES + VALIDATE_RUNTIME_FILES + ('LICENSE.txt',):
        src = os.path.join(src_root, name)
        if os.path.isfile(src):
            shutil.copy(src, os.path.join(dst, name))
    ignore = shutil.ignore_patterns('__pycache__', '*.pyc', '*.lua')
    shutil.copytree(os.path.join(src_root, 'generator'), os.path.join(dst, 'generator'), ignore=ignore)
    tool = os.path.join(dst, 'tools', 'wireshark')
    shutil.copytree(os.path.join(src_root, 'tools', 'wireshark', 'backend'), os.path.join(tool, 'backend'),
                    ignore=ignore)
    for name in ('nanopb_any_dissector.lua', 'nanopb_studio.lua'):
        shutil.copy(os.path.join(src_root, 'tools', 'wireshark', name), os.path.join(tool, name + '.src'))
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
    keys = ['python', 'project', 'nanopb_root', 'protos_root', 'output_dir', 'extra_includes', 'port_map']
    keys += sorted(k for k in config if k not in keys)
    with open(config_path, 'w', newline='\n') as handle:
        handle.write('-- nanopb studio state (written by install-studio and the Tools > nanopb dialogs)\n'
                     'return {\n')
        for key in keys:
            handle.write('  %s = %s,\n' % (key, lua_str(config.get(key, ''))))
        handle.write('}\n')
    files += [project, config_path]
    return {'plugins_dir': plugins, 'project': project, 'files': files, 'warnings': warnings,
            'mode': 'dev (uses %s)' % config['nanopb_root'] if args.dev else 'self-contained'}


IMPORT_RE = re.compile(r'^\s*import\s+(?:public\s+|weak\s+)?"([^"]+)"', re.M)


def merged_into(protos_root, units):
    """{unit: [units that import it]}: their merged .c/.h already contain it.

    Found by scanning import lines, so it needs no protoc run.
    """

    result = {}
    for name in units:
        unit_dir = os.path.join(protos_root, name)
        for proto in unit_protos(unit_dir):
            with open(os.path.join(unit_dir, proto), encoding='utf-8', errors='replace') as handle:
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
        p.add_argument('--protos-root', required=True, help='directory whose subdirectories are units')
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

    p = sub.add_parser('install-dissector', help='install dissector + schema into a plugins dir')
    protos_args(p)
    p.add_argument('--plugins-dir', default=None, help='default: personal Wireshark plugins folder')
    p.add_argument('--port-map', default=None, help='e.g. "udp:5000=pkg.Envelope,tcp:7000=pkg.Cmd"')
    p.set_defaults(func=cmd_install_dissector)

    p = sub.add_parser('gen-packets', help='one capture with valid (PASSED) and invalid (DROPPED) packets')
    protos_args(p, unit=True)
    p.add_argument('--out', required=True, help='output directory for nanopb_test_packets.{pcapng,json,txt}')
    p.add_argument('--port-map', default='',
                   help='root messages sent on their own port (default: one UDP port per unit root, from %d)'
                   % AUTO_PORT_BASE)
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

    p = sub.add_parser('install-studio', help='install nanopb_studio.lua into a plugins dir')
    p.add_argument('--plugins-dir', default=None, help='default: personal Wireshark plugins folder')
    p.add_argument('--dev', action='store_true',
                   help='run this checkout instead of the copy (edits take effect without reinstalling)')
    p.set_defaults(func=cmd_install_studio)
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    status = 1
    try:
        args.nanopb_root = os.path.abspath(args.nanopb_root)
        setup_nanopb(args.nanopb_root)
        if hasattr(args, 'protos_root'):
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
