"""Shared helpers for the validate/ Python tests."""

import contextlib
import io
import json
import os
import struct
import sys

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
VALIDATE_DIR = os.path.dirname(os.path.dirname(TESTS_DIR))
REPO_ROOT = os.path.dirname(VALIDATE_DIR)
PKG_DIR = os.path.join(VALIDATE_DIR, 'nanopb_validate')
# The Wireshark Lua plugins.
TOOL_DIR = os.path.join(VALIDATE_DIR, 'wireshark')
EXAMPLES_DIR = os.path.join(VALIDATE_DIR, 'examples')
STRESS_PROTOS = os.path.join(EXAMPLES_DIR, 'stress', 'protos')
VALIDATE_PROTO_DIR = os.path.join(PKG_DIR, 'validate_proto')
WIRESHARK_INCLUDE = os.path.join(PKG_DIR, 'wireshark_include')
C_TESTS_DIR = os.path.join(VALIDATE_DIR, 'tests', 'c')
FIXTURES = os.path.join(TESTS_DIR, 'fixtures', 'protos')


def option_proto(name):
    """Path of validate.proto (ours) or nanopb.proto (nanopb's generator/proto)."""

    if name == 'validate':
        return os.path.join(VALIDATE_PROTO_DIR, 'validate.proto')
    return os.path.join(REPO_ROOT, 'generator', 'proto', name + '.proto')


# The tests use the text list; the tick box window needs someone to click it.
os.environ['NANOPB_WS_NO_TK'] = '1'

sys.path.insert(0, PKG_DIR)
import backend  # noqa: E402  (the engine behind python -m nanopb_validate)


def run_backend(*argv):
    """Run the backend in-process; returns (status, parsed JSON or None, stderr)."""

    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        status = backend.main(list(argv))
    text = out.getvalue()
    assert text.rstrip().endswith('__EXIT__=%d' % status), text
    body = text.rstrip()[:-len('__EXIT__=%d' % status)].strip()
    return status, (json.loads(body) if body else None), err.getvalue()


# Minimal protobuf encoder for building exact test vectors.

def varint(n):
    if n < 0:
        n += 1 << 64
    out = bytearray()
    while True:
        b = n & 0x7f
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def key(number, wire):
    return varint((number << 3) | wire)


def f_varint(number, value):
    return key(number, 0) + varint(value)


def f_sint(number, value):
    return f_varint(number, (value << 1) ^ (value >> 63))


def f_bytes(number, data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    return key(number, 2) + varint(len(data)) + data


def f_fixed32(number, fmt, value):
    return key(number, 5) + struct.pack('<' + fmt, value)


def f_fixed64(number, fmt, value):
    return key(number, 1) + struct.pack('<' + fmt, value)


def any_of(type_name, payload):
    return f_bytes(1, 'type.googleapis.com/' + type_name) + f_bytes(2, payload)
