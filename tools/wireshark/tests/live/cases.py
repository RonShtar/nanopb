"""Test packets for checking the nanopb dissector in a real Wireshark.

Every case has an exactly known payload (built with the encoder in
tests/helpers.py) and the tree lines / expert messages / display filter
that Wireshark must show for it. The same cases drive the mock tests
(test_dissector.py), the pcap self-check and `live_test.py verify`.

Expected strings are compared case-insensitively (Wireshark prints
booleans as "True", the mock as "true").
"""

import os
import shutil
import sys
import tempfile

LIVE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(LIVE_DIR))

from helpers import (FIXTURES, any_of, f_bytes, f_fixed32, f_fixed64, f_sint,  # noqa: E402
                     f_varint, run_backend, varint)

# Port map installed by `live_test.py setup` and used by `verify`.
PORT_MAP = 'udp:5000=demo.envelope.Envelope,tcp:7000=demo.telemetry.Telemetry'
DECODE_AS_PORT = 6001
DECODE_AS_MESSAGE = 'demo.payloads.Ping'


class Case(object):
    def __init__(self, name, transport, port, payload, expect, experts=(), filter=None,
                 how='port', note=''):
        self.name = name
        self.transport = transport
        self.port = port
        self.payload = payload
        self.expect = list(expect)
        self.experts = list(experts)
        self.filter = filter
        # 'port' = port map, 'heuristic' = Any heuristic, 'decode_as' = needs
        # Decode As + Default message pref.
        self.how = how
        self.note = note


def _envelope_command():
    ping = f_varint(1, 7)
    command = f_bytes(1, 'go') + f_varint(2, -5) + f_bytes(3, ping)
    return (f_varint(1, 3) + f_bytes(2, any_of('demo.payloads.Command', command))
            + f_bytes(3, f_varint(1, 9)))


def _nested_any():
    inner = f_varint(1, 1) + f_bytes(2, any_of('demo.payloads.Ping', f_varint(1, 42)))
    return f_varint(1, 2) + f_bytes(2, any_of('demo.envelope.Envelope', inner))


def _telemetry():
    header = f_varint(1, 1) + f_fixed64(2, 'Q', 1234567890123) + f_bytes(3, 's1')
    reading = f_varint(1, 1) + f_fixed32(2, 'f', 21.5) + f_sint(3, -3)
    packed = varint((1 << 64) - 1) + varint(300)  # int32 -1 is a 10-byte varint
    return (f_bytes(1, header) + f_bytes(2, 'dev') + f_bytes(3, reading) + f_bytes(4, packed)
            + f_bytes(5, b'\x01\x02') + f_fixed64(6, 'd', 0.25) + f_varint(7, 1))


CASES = [
    Case('Envelope with Any -> Command', 'udp', 5000, _envelope_command(),
         ['nanopb Protobuf: demo.envelope.Envelope', 'version: 3',
          'body (2): google.protobuf.Any -> demo.payloads.Command',
          'Any type_url: type.googleapis.com/demo.payloads.Command',
          'value: Any -> demo.payloads.Command', 'name: go', 'arg: -5',
          'inner (3): demo.payloads.Ping', 'id: 7', 'last_ping (3): demo.payloads.Ping', 'id: 9'],
         filter='nanopb.type_url contains "Command"'),
    Case('Nested Any: Envelope -> Any(Envelope -> Any(Ping))', 'udp', 5000, _nested_any(),
         ['value: Any -> demo.envelope.Envelope', 'value: Any -> demo.payloads.Ping', 'id: 42'],
         filter='nanopb.demo.payloads.Ping.id == 42'),
    Case('Telemetry, every scalar kind (TCP)', 'tcp', 7000, _telemetry(),
         ['nanopb Protobuf: demo.telemetry.Telemetry', 'seq: 1', 'timestamp_us: 1234567890123',
          'source: s1', 'device_name: dev', 'unit: UNIT_CELSIUS (1)', 'value: 21.5', 'offset: -3',
          'raw (4): packed [2]', 'raw: -1', 'raw: 300', 'blob: 0102', 'ratio: 0.25', 'healthy: true'],
         filter='nanopb.demo.telemetry.Telemetry.device_name == "dev" && nanopb.demo.telemetry.Reading.offset == -3'),
    Case('Bare Any on an unmapped port (heuristic)', 'udp', 6000,
         any_of('demo.payloads.Ping', f_varint(1, 99)),
         ['nanopb Protobuf: google.protobuf.Any', 'value: Any -> demo.payloads.Ping', 'id: 99'],
         filter='nanopb.demo.payloads.Ping.id == 99', how='heuristic',
         note='Found by "Detect Any on any port (heuristic)"; disable that pref and it shows as plain UDP data.'),
    Case('Any with a type that is not in the schema', 'udp', 5000,
         f_varint(1, 1) + f_bytes(2, any_of('other.Thing', b'\x08\x01')),
         ['body (2): google.protobuf.Any -> other.Thing', 'value: 2 bytes (type other.Thing not in schema)'],
         experts=['Any type not in schema: other.Thing'], filter='nanopb.any.unknown_type'),
    Case('Malformed: length runs past the end', 'udp', 5000, f_varint(1, 1) + b'\x12\x10\x01',
         ['nanopb Protobuf: demo.envelope.Envelope', 'version: 1'],
         experts=['Length exceeds message'], filter='nanopb.malformed'),
    Case('Plain Ping on port %d (Decode As)' % DECODE_AS_PORT, 'udp', DECODE_AS_PORT, f_varint(1, 5),
         ['nanopb Protobuf: demo.payloads.Ping', 'id: 5'],
         filter='nanopb.demo.payloads.Ping.id == 5', how='decode_as',
         note='Not decoded by default. Analyze > Decode As: UDP port %d -> NANOPB, and set '
              'Preferences > Protocols > NANOPB > Default message = %s.' % (DECODE_AS_PORT, DECODE_AS_MESSAGE)),
]


def generated_cases(count=5, seed=1):
    """Random valid Envelopes from the data generator (gen-data)."""

    tmp = tempfile.mkdtemp(prefix='nanopb_ws_live_')
    try:
        status, result, err = run_backend('gen-data', '--protos-root', FIXTURES, '--unit', 'envelope',
                                          '--messages', 'Envelope', '--formats', 'bin',
                                          '--count', str(count), '--seed', str(seed), '--out', tmp)
        if status != 0:
            raise RuntimeError('gen-data failed: %s' % err)
        cases = []
        for i in range(count):
            name = 'demo_envelope_Envelope_%d.bin' % i if count > 1 else 'demo_envelope_Envelope.bin'
            with open(os.path.join(tmp, 'envelope', 'data', name), 'rb') as handle:
                payload = handle.read()
            cases.append(Case('Generated Envelope #%d (gen-data --seed %d)' % (i, seed), 'udp', 5000, payload,
                              ['nanopb Protobuf: demo.envelope.Envelope',
                               'Any type_url: type.googleapis.com/demo.payloads.'],
                              filter='nanopb.message == "demo.envelope.Envelope"'))
        return cases
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def all_cases(generated=5, seed=1):
    return CASES + (generated_cases(generated, seed) if generated else [])
