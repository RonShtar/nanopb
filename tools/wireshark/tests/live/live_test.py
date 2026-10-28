#!/usr/bin/env python3
"""Check the nanopb Wireshark plugins in a real Wireshark.

  setup      install nanopb_studio.lua + the dissector (schema of the test
             protos, test port map) into your personal plugins folder
  pcap       write a capture with one packet per test case
  send       send the same packets as live UDP/TCP traffic (capture loopback)
  checklist  write CHECKLIST.md: what Wireshark must show for each packet
  verify     run the checks automatically with tshark

Typical run:
  python tools/wireshark/tests/live/live_test.py setup
  (Wireshark: Ctrl+Shift+L)
  python tools/wireshark/tests/live/live_test.py pcap
  (open nanopb_live_test.pcap, compare with CHECKLIST.md)
  python tools/wireshark/tests/live/live_test.py verify --pcap nanopb_live_test.pcap
"""

from __future__ import print_function

import argparse
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

LIVE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, LIVE_DIR)

from cases import DECODE_AS_MESSAGE, DECODE_AS_PORT, PORT_MAP, all_cases  # noqa: E402
from helpers import FIXTURES, REPO_ROOT, TOOL_DIR, run_backend  # noqa: E402
import nanopb_wireshark  # noqa: E402

SRC_PORT_BASE = 40000

# tshark prints UTF-8 (interface names can be non-ASCII); don't decode it
# with the Windows ANSI code page.
TEXT = {'encoding': 'utf-8', 'errors': 'replace'}

# Expert messages raised by nanopb_any_dissector.lua.
EXPERT_TEXTS = ('Truncated', 'Length exceeds message', 'Field number 0', 'Unsupported wire type',
                'Bad packed element', 'Any type not in schema', 'Root message not in schema',
                'Maximum nesting depth', 'nanopb schema not found')
LOOPBACK = socket.inet_aton('127.0.0.1')

# ---------------------------------------------------------------------------
# pcap
# ---------------------------------------------------------------------------


ip_checksum = nanopb_wireshark.ip_checksum


def frame(case, index):
    return nanopb_wireshark.ethernet_frame(case.transport, case.port, case.payload, index)


def write_pcap(path, cases):
    packets = [nanopb_wireshark.Packet(c.transport, c.port, c.payload) for c in cases]
    nanopb_wireshark.write_pcap(path, packets, start=int(time.time()))


LINK_HEADER = {0: 4, 1: 14, 101: 0, 113: 16, 228: 0}  # NULL, Ethernet, RAW, Linux SLL, IPv4


def read_pcap(path, all_packets=False):
    """Returns [(transport, src_port, dst_port, payload, ip_checksum_ok)].

    With all_packets=True, returns (frame_number, ...) tuples for every
    IPv4 UDP/TCP packet with a payload (used for live captures).
    """

    packets = []
    with open(path, 'rb') as handle:
        data = handle.read()
    magic, = struct.unpack('<I', data[:4])
    assert magic == 0xa1b2c3d4, 'not a little-endian classic pcap'
    linktype, = struct.unpack('<I', data[20:24])
    skip = LINK_HEADER.get(linktype)
    assert skip is not None, 'unsupported link type %d' % linktype
    pos = 24
    number = 0
    while pos < len(data):
        _, _, incl, _ = struct.unpack('<IIII', data[pos:pos + 16])
        pkt = data[pos + 16:pos + 16 + incl]
        pos += 16 + incl
        number += 1
        ip = pkt[skip:]
        if len(ip) < 20 or ip[0] >> 4 != 4 or ip[9] not in (6, 17):
            if all_packets:
                continue
            raise AssertionError('packet %d is not IPv4 UDP/TCP' % number)
        ihl = (ip[0] & 0x0f) * 4
        total = struct.unpack('!H', ip[2:4])[0]
        checksum_ok = ip_checksum(ip[:ihl]) == 0
        l4 = ip[ihl:total]
        sport, dport = struct.unpack('!HH', l4[:4])
        if ip[9] == 17:
            entry = ('udp', sport, dport, l4[8:], checksum_ok)
        else:
            entry = ('tcp', sport, dport, l4[(l4[12] >> 4) * 4:], checksum_ok)
        if all_packets:
            if entry[3]:
                packets.append((number,) + entry)
        else:
            packets.append(entry)
    return packets


def match_frames(path, cases):
    """Map case number -> first captured frame carrying exactly its payload."""

    packets = read_pcap(path, all_packets=True)
    frames = {}
    for number, case in enumerate(cases, 1):
        for frame_no, transport, _, dport, payload, _ in packets:
            if (transport, dport, payload) == (case.transport, case.port, case.payload):
                frames[number] = frame_no
                break
    return frames


def loopback_interface(tshark):
    out = subprocess.run([tshark, '-D'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         **TEXT).stdout
    for line in out.splitlines():
        match = re.match(r'^\s*\d+\.\s+(\S+)(.*)$', line)
        if match and ('loopback' in line.lower() or match.group(1) == 'lo'):
            return match.group(1)
    raise RuntimeError('no loopback capture interface found in tshark -D:\n' + out)


def live(cases, isolated, interface, keep):
    """Capture loopback with tshark while sending the cases, then verify."""

    tshark = find_tshark()
    if not tshark:
        raise RuntimeError('tshark not found (install Wireshark with tshark, or set TSHARK=<path>)')
    interface = interface or loopback_interface(tshark)
    ports = sorted(set((c.transport, c.port) for c in cases))
    capture_filter = ' or '.join('%s port %d' % p for p in ports)
    workdir = tempfile.mkdtemp(prefix='nanopb_ws_live_')
    pcap = keep or os.path.join(workdir, 'live_capture.pcap')
    proc = subprocess.Popen([tshark, '-i', interface, '-f', capture_filter, '-F', 'pcap', '-w', pcap],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, **TEXT)
    try:
        time.sleep(3)  # let the capture start
        if proc.poll() is not None:
            raise RuntimeError('tshark capture failed:\n' + proc.stdout.read())
        send(cases, '127.0.0.1', 1, 0.1)
        time.sleep(2)
    finally:
        proc.terminate()
        proc.wait(10)
    frames = match_frames(pcap, cases)
    print('captured %d/%d test packets on %s -> %s' % (len(frames), len(cases), interface, pcap))
    try:
        return verify(pcap, cases, isolated, frames)
    finally:
        if not keep:
            shutil.rmtree(workdir, ignore_errors=True)


# ---------------------------------------------------------------------------
# send
# ---------------------------------------------------------------------------


def send(cases, host, repeat, interval):
    tcp_ports = sorted(set(c.port for c in cases if c.transport == 'tcp'))
    listeners = []
    for port in tcp_ports:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            srv.bind((host, port))
        except OSError as exc:
            raise SystemExit('cannot listen on tcp/%d (%s); free the port and retry' % (port, exc))
        srv.listen(8)

        def drain(s=srv):
            while True:
                try:
                    conn, _ = s.accept()
                except OSError:
                    return
                while conn.recv(65536):
                    pass
                conn.close()
        threading.Thread(target=drain, daemon=True).start()
        listeners.append(srv)

    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        for round_no in range(repeat):
            for i, case in enumerate(cases):
                if case.transport == 'udp':
                    udp.sendto(case.payload, (host, case.port))
                else:
                    conn = socket.create_connection((host, case.port))
                    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    conn.sendall(case.payload)
                    time.sleep(0.05)
                    conn.close()
                print('[%d/%d] case %d %s/%d: %s' % (round_no + 1, repeat, i + 1, case.transport,
                                                    case.port, case.name))
                time.sleep(interval)
    finally:
        udp.close()
        time.sleep(0.2)
        for srv in listeners:
            srv.close()


# ---------------------------------------------------------------------------
# setup / checklist
# ---------------------------------------------------------------------------


def setup(plugins_dir, reset_config, out_dir):
    plugins = plugins_dir or nanopb_wireshark.default_plugins_dir()
    config = os.path.join(plugins, 'nanopb', 'studio_config.luadata')
    lua = nanopb_wireshark.lua_str
    if reset_config or not os.path.exists(config):
        os.makedirs(os.path.dirname(config), exist_ok=True)
        with open(config, 'w', newline='\n') as handle:
            handle.write('-- written by tools/wireshark/tests/live/live_test.py setup\nreturn {\n')
            for key, value in (('python', sys.executable), ('nanopb_root', REPO_ROOT),
                               ('protos_root', FIXTURES), ('output_dir', out_dir), ('extra_includes', ''),
                               ('port_map', PORT_MAP)):
                handle.write('  %s = %s,\n' % (key, lua(value)))
            handle.write('}\n')
        print('studio settings -> test fixtures: %s' % config)
    else:
        print('kept existing studio settings (%s); use --reset-config to point them at the test fixtures'
              % config)
    for argv in (('install-studio', '--plugins-dir', plugins),
                 ('install-dissector', '--protos-root', FIXTURES, '--plugins-dir', plugins,
                  '--port-map', PORT_MAP)):
        status, result, err = run_backend(*argv)
        if status != 0:
            raise SystemExit('%s failed:\n%s' % (argv[0], err))
        for path in result['files']:
            print('installed %s' % path)
    print('\nIn Wireshark: Analyze > Reload Lua Plugins (Ctrl+Shift+L), or restart it.')
    print('Check Help > About Wireshark > Plugins lists nanopb_studio.lua and nanopb_any_dissector.lua.')
    return plugins


def checklist_markdown(cases):
    out = ['# nanopb Wireshark live checklist', '',
           'Generated by `python tools/wireshark/tests/live/live_test.py checklist`; do not edit.', '',
           '## 1. Install', '',
           '1. `python tools/wireshark/tests/live/live_test.py setup` (add `--reset-config` if you already '
           'configured the studio for your own protos).',
           '2. Wireshark: **Analyze > Reload Lua Plugins** (Ctrl+Shift+L).',
           '3. **Help > About Wireshark > Plugins** lists `nanopb_studio.lua` and `nanopb_any_dissector.lua` '
           'with no load errors.',
           '4. **Edit > Preferences > Protocols > NANOPB** shows Port map = `%s`, '
           '"Treat unknown payload as Any" and "Detect Any on any port (heuristic)" both checked.' % PORT_MAP,
           '',
           '## 2. Packets', '',
           'Open `nanopb_live_test.pcap` (`live_test.py pcap`), or capture on loopback (Windows: '
           '*Adapter for loopback traffic capture*, Linux: `lo`) with filter `udp or tcp port 7000` while running '
           '`live_test.py send`. In the pcap, packet *N* is case *N*. Expand **nanopb Protobuf** in the '
           'packet details for each packet.', '']
    for i, case in enumerate(cases, 1):
        out.append('### Packet %d: %s' % (i, case.name))
        out.append('')
        out.append('- Transport: %s port %d (%s)' % (case.transport.upper(), case.port,
                                                    {'port': 'port map', 'heuristic': 'heuristic',
                                                     'decode_as': 'Decode As'}[case.how]))
        if case.note:
            out.append('- Note: %s' % case.note)
        out.append('- The tree contains:')
        for line in case.expect:
            out.append('  - [ ] `%s`' % line)
        for line in case.experts:
            out.append('  - [ ] expert info `%s`' % line)
        if not case.experts:
            out.append('  - [ ] no expert info from nanopb')
        if case.filter:
            out.append('- [ ] Display filter `%s` shows this packet' % case.filter)
        out.append('')
    out += ['## 3. Preferences', '',
            '- [ ] Untick **Detect Any on any port (heuristic)**: packet 4 becomes plain UDP data. Tick it again.',
            '- [ ] Change **Port map** to remove `udp:5000=...`: packets on 5000 are now only decoded when '
            'they look like an Any (heuristic); put it back.',
            '- [ ] **Analyze > Decode As...**: add *UDP port* %d -> *NANOPB*, and set **Default message** to '
            '`%s`: packet 7 decodes as described above.' % (DECODE_AS_PORT, DECODE_AS_MESSAGE),
            '',
            '## 4. Tools > nanopb menu', '',
            '- [ ] The menu has exactly **Generate C (merged + validation)**, **Generate test packets (passed + '
            'dropped)**, **Install or update dissector** and **About**. **About** shows the plugins folder, the '
            'installed project copy and the last input directory = the test fixtures.',
            '- [ ] **Generate C (merged + validation)**: the dialog only asks for input and output. The unit list '
            'shows `[x] envelope` and `[x] telemetry`; click `telemetry` (now `[ ]`), press **Generate**: OK, and '
            'the result lists `demo_envelope_Envelope_filter_udp`; **Open output folder** shows only `envelope/` '
            'with `envelope.c`, `envelope.h` and the separate `pb*.c/.h` runtime files including `pb_validate.c`.',
            '- [ ] In the same unit list press **Select none**, then **Generate**: the list says '
            '"Select at least one unit." and nothing is generated.',
            '- [ ] **Generate test packets**, both units: the result says how many packets are expected PASSED and '
            'DROPPED; `nanopb_test_packets.pcapng` opens by itself. Every packet has a **Validation: PASSED** or '
            '**Validation: DROPPED** subtree matching its packet comment (`expect=...`).',
            '- [ ] In that result window, **Show dropped only** applies `nanopb.validation == "dropped"` and only '
            'the DROPPED packets remain; **Show all** brings the others back.',
            '- [ ] Run **Generate test packets** again: the capture reopens without reloading Lua plugins (the schema '
            'did not change).',
            '- [ ] **Generate C** with input `nope`: shows FAILED with "is not a directory".',
            '- [ ] **Install or update dissector**, input prefilled, port map `%s`: OK, then plugins reload and '
            'packets still decode.' % PORT_MAP,
            '']
    return '\n'.join(out)


# ---------------------------------------------------------------------------
# verify (tshark)
# ---------------------------------------------------------------------------


def find_tshark():
    candidates = [os.environ.get('TSHARK'), shutil.which('tshark')]
    if os.name == 'nt':
        for base in (os.environ.get('ProgramFiles'), os.environ.get('ProgramFiles(x86)')):
            if base:
                candidates.append(os.path.join(base, 'Wireshark', 'tshark.exe'))
    for cand in candidates:
        if cand and os.path.isfile(cand):
            return cand
    return None


def installed_dissector():
    path = os.path.join(nanopb_wireshark.default_plugins_dir(), 'nanopb_any_dissector.lua')
    return path if os.path.isfile(path) else None


def tshark_base(tshark, isolated, workdir, port_map=PORT_MAP, protos_root=FIXTURES):
    """Command prefix and environment for running tshark with the dissector."""

    argv = [tshark, '-o', 'nanopb.port_map:' + port_map]
    env = dict(os.environ)
    if isolated:
        # A throwaway personal config dir: no installed plugins (they would
        # clash with the repo copy) and no user preferences.
        env['WIRESHARK_CONFIG_DIR'] = os.path.join(workdir, 'wireshark-config')
        os.makedirs(env['WIRESHARK_CONFIG_DIR'], exist_ok=True)
        schema = os.path.join(workdir, 'schema.luadata')
        status, _, err = run_backend('schema', '--protos-root', protos_root, '--out', schema)
        if status != 0:
            raise RuntimeError('schema failed: %s' % err)
        env['NANOPB_WS_SCHEMA'] = schema
        argv[1:1] = ['-X', 'lua_script:' + os.path.join(TOOL_DIR, 'nanopb_any_dissector.lua')]
    elif not installed_dissector():
        raise RuntimeError('nanopb_any_dissector.lua is not installed; run live_test.py setup first')
    return argv, env


def run(argv, env):
    proc = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          env=env, **TEXT)
    return proc.returncode, proc.stdout


def split_frames(text):
    frames = {}
    current = None
    for line in text.splitlines():
        match = re.match(r'^Frame (\d+):', line)
        if match:
            current = int(match.group(1))
            frames[current] = []
        elif current is not None:
            frames[current].append(line)
    return dict((k, '\n'.join(v)) for k, v in frames.items())


def verify(pcap, cases, isolated=False, frames=None, port_map=PORT_MAP, protos_root=FIXTURES,
           decode_as_port=DECODE_AS_PORT, decode_as_message=DECODE_AS_MESSAGE):
    """Returns a list of (case_number, case, [problems]).

    ``frames`` maps case number -> frame number (default: identical, as in
    the pcap written by write_pcap)."""

    tshark = find_tshark()
    if not tshark:
        raise RuntimeError('tshark not found (install Wireshark with tshark, or set TSHARK=<path>)')
    workdir = tempfile.mkdtemp(prefix='nanopb_ws_verify_')
    try:
        base, env = tshark_base(tshark, isolated, workdir, port_map, protos_root)
        decode_as = ['-d', 'udp.port==%d,nanopb' % decode_as_port,
                     '-o', 'nanopb.default_message:' + decode_as_message]
        views = {}
        for key, extra in (('normal', []), ('decode_as', decode_as)):
            status, out = run(base + extra + ['-r', pcap, '-V'], env)
            if status != 0:
                raise RuntimeError('tshark failed:\n' + out)
            views[key] = split_frames(out)

        results = []
        for number, case in enumerate(cases, 1):
            frame_no = number if frames is None else frames.get(number)
            if frame_no is None:
                results.append((number, case, ['packet not captured']))
                continue
            extra = decode_as if case.how == 'decode_as' else []
            text = views['decode_as' if case.how == 'decode_as' else 'normal'].get(frame_no, '')
            low = text.lower()
            problems = ['missing: %s' % e for e in case.expect if e.lower() not in low]
            problems += ['missing expert: %s' % e for e in case.experts if e.lower() not in low]
            if not case.experts:
                problems += ['unexpected expert: %s' % e for e in EXPERT_TEXTS if e.lower() in low]
            if case.filter:
                status, out = run(base + extra + ['-r', pcap, '-Y', case.filter, '-T', 'fields',
                                                  '-e', 'frame.number'], env)
                matched = set(int(x) for x in out.split() if x.isdigit())
                if status != 0 or frame_no not in matched:
                    problems.append('filter did not match: %s %s' % (case.filter,
                                                                     out.strip()[:200] if status else ''))
            results.append((number, case, problems))
        return results
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('--generated', type=int, default=5,
                        help='number of random gen-data Envelopes appended to the cases (default 5)')
    parser.add_argument('--seed', type=int, default=1, help='seed for the generated Envelopes')
    sub = parser.add_subparsers(dest='command')
    sub.required = True

    p = sub.add_parser('setup', help='install plugins + test schema into the personal plugins folder')
    p.add_argument('--plugins-dir', default=None)
    p.add_argument('--reset-config', action='store_true',
                   help='point nanopb studio settings at the test fixtures even if already configured')
    p.add_argument('--out-dir', default=os.path.abspath('nanopb_live_out'),
                   help='studio output directory for the menu tests')

    p = sub.add_parser('pcap', help='write the test capture')
    p.add_argument('--out', default='nanopb_live_test.pcap')

    p = sub.add_parser('send', help='send the test packets as live traffic')
    p.add_argument('--host', default='127.0.0.1')
    p.add_argument('--repeat', type=int, default=1)
    p.add_argument('--interval', type=float, default=0.5)

    p = sub.add_parser('checklist', help='write the manual checklist')
    p.add_argument('--out', default=os.path.join(LIVE_DIR, 'CHECKLIST.md'))

    p = sub.add_parser('verify', help='check a capture with tshark')
    p.add_argument('--pcap', default='nanopb_live_test.pcap')
    p.add_argument('--isolated', action='store_true',
                   help='load the dissector from this repo with a fresh schema in a throwaway Wireshark '
                        'config, instead of the installed copy')

    p = sub.add_parser('live', help='capture loopback with tshark while sending, then verify')
    p.add_argument('--interface', default=None, help='capture interface (default: the loopback one)')
    p.add_argument('--keep', default=None, help='keep the capture at this path')
    p.add_argument('--isolated', action='store_true',
                   help='load the dissector from this repo with a fresh schema instead of the installed copy')

    args = parser.parse_args(argv)
    cases = all_cases(args.generated, args.seed)

    if args.command == 'setup':
        setup(args.plugins_dir, args.reset_config, args.out_dir)
    elif args.command == 'pcap':
        write_pcap(args.out, cases)
        print('wrote %s: %d packets' % (os.path.abspath(args.out), len(cases)))
        for i, case in enumerate(cases, 1):
            print('  %2d  %s/%-5d %s' % (i, case.transport, case.port, case.name))
    elif args.command == 'send':
        send(cases, args.host, args.repeat, args.interval)
    elif args.command == 'checklist':
        with open(args.out, 'w', newline='\n') as handle:
            handle.write(checklist_markdown(cases))
        print('wrote %s' % args.out)
    elif args.command in ('verify', 'live'):
        try:
            if args.command == 'verify':
                results = verify(args.pcap, cases, args.isolated)
            else:
                results = live(cases, args.isolated, args.interface, args.keep)
        except RuntimeError as exc:
            print('error: %s' % exc)
            return 2
        failed = 0
        for number, case, problems in results:
            print('%-4s %2d  %s' % ('PASS' if not problems else 'FAIL', number, case.name))
            for problem in problems:
                print('          ' + problem)
            failed += bool(problems)
        print('\n%d/%d cases passed' % (len(results) - failed, len(results)))
        return 1 if failed else 0
    return 0


if __name__ == '__main__':
    sys.exit(main())
