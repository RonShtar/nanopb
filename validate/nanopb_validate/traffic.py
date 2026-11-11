"""Test data: sample messages (valid / invalid), pcap/pcapng captures and C arrays
(packets PROTOS_DIR).
"""

import json
import shutil
import os
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from protos import (BackendError, Unit, c_identifier, parse_port_map, protocol_messages, protocol_name,  # noqa: E402
                    select_units, unit_data_generator, unit_entrypoints, unit_root)
from wireshark import (default_plugins_dir, install_schema, prune_port_map, schema_text, stale_ports_note)  # noqa: E402


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
    """The packets of each unit as text files, next to the capture:

        <out>/<unit>/packets/c_arrays/c_arrays_passed.txt    every PASSED packet as a C array
        <out>/<unit>/packets/c_arrays/c_arrays_dropped.txt   every DROPPED packet as a C array
        <out>/<unit>/packets/raw_data/<Message>_passed.txt   one hex stream per line
        <out>/<unit>/packets/raw_data/<Message>_dropped.txt

    Each entry gets 'files' = [its C array file, its hex stream file]. The
    packets/ folder is rewritten, so it always matches the capture.
    Returns the packets/ directories.
    """

    by_dir = {}
    for entry in entries:
        by_dir.setdefault(os.path.join(out, entry['unit'], 'packets'), []).append(entry)
    for directory, unit_entries in by_dir.items():
        if os.path.isdir(directory):
            shutil.rmtree(directory)
        c_dir, raw_dir = os.path.join(directory, 'c_arrays'), os.path.join(directory, 'raw_data')
        os.makedirs(c_dir)
        os.makedirs(raw_dir)
        arrays = {'passed': [], 'dropped': []}
        streams = {}
        for entry in unit_entries:
            verdict = entry['expect']
            message = c_identifier(entry['message'].replace('.', '_'))
            ident = 'packet_%03d_%s_%s' % (entry['frame'], message, verdict)
            data = bytes.fromhex(entry['hex'])
            why = ''
            if entry.get('violate'):
                why = ', breaks %s.%s' % (entry['violate'].get('field', '?'), entry['violate'].get('rule', '?'))
            rows = ',\n'.join('    ' + ', '.join('0x%02x' % b for b in data[i:i + 12]) for i in range(0, len(data), 12))
            arrays[verdict].append('/* frame %d: %s, %s%s, %d bytes */\nstatic const uint8_t %s[%d] = {\n%s\n};\n'
                                   % (entry['frame'], entry['message'], verdict.upper(), why, len(data), ident,
                                      max(len(data), 1), rows or '    0x00'))
            raw_name = '%s_%s.txt' % (message, verdict)
            # Both files exist for every message (empty when, e.g., it has no rule to break).
            for other in ('passed', 'dropped'):
                streams.setdefault('%s_%s.txt' % (message, other), [])
            streams[raw_name].append(entry['hex'])
            entry['files'] = [os.path.join(c_dir, 'c_arrays_%s.txt' % verdict), os.path.join(raw_dir, raw_name)]
        for verdict, items in arrays.items():
            with open(os.path.join(c_dir, 'c_arrays_%s.txt' % verdict), 'w', newline='\n') as handle:
                handle.write('/* %s packets of %s, generated by nanopb validate. */\n#include <stdint.h>\n\n'
                             % (verdict.upper(), os.path.basename(os.path.dirname(directory))))
                handle.write('\n'.join(items))
        for name, lines in streams.items():
            with open(os.path.join(raw_dir, name), 'w', newline='\n') as handle:
                handle.write(''.join(line + '\n' for line in lines))
    return sorted(by_dir)


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
