"""Shared helpers for the tools/wireshark tests."""

import contextlib
import io
import json
import os
import struct
import sys

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
TOOL_DIR = os.path.dirname(TESTS_DIR)
REPO_ROOT = os.path.dirname(os.path.dirname(TOOL_DIR))
FIXTURES = os.path.join(TESTS_DIR, 'fixtures', 'protos')

sys.path.insert(0, os.path.join(TOOL_DIR, 'backend'))
import nanopb_wireshark  # noqa: E402


def run_backend(*argv):
    """Run the backend in-process; returns (status, parsed JSON or None, stderr)."""

    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        status = nanopb_wireshark.main(list(argv))
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
