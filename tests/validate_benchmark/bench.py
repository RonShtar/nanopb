#!/usr/bin/env python3
"""Validation benchmark: ns per packet and stack use, per build configuration.

Generates bench.proto with nanopb + nanopb-validate (--filter=Envelope),
builds bench_validate_main.c with -O2 in each configuration below and prints
markdown tables (the numbers in docs/validation_performance.md come from it).

    python tests/validate_benchmark/bench.py [--iterations N] [--cc "zig cc"]

The compiler is taken from --cc, $CC, gcc/clang on PATH, or `pip install
ziglang` (python -m ziglang cc).
"""

import argparse
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))

CONFIGS = [
    ('default', []),
    ('PB_VALIDATE_DEBUG', ['-DPB_VALIDATE_DEBUG']),
    ('PB_BUFFER_ONLY + PB_NO_ERRMSG', ['-DPB_BUFFER_ONLY', '-DPB_NO_ERRMSG']),
    ('PB_VALIDATE_FILTER_STATIC_BUFFERS', ['-DPB_VALIDATE_FILTER_STATIC_BUFFERS']),
]

OPERATIONS = ('decode', 'decode+validate', 'decode+validate(NULL)', 'filter_udp')
PACKETS = ('valid', 'bad_first', 'bad_last')

TIME_RE = re.compile(r'^(\S+)\s+(\S+)\s+([\d.]+) ns$')
STACK_RE = re.compile(r'^stack (\S+)\s+(\d+)$')
SIZE_RE = re.compile(r'^(?:sizeof )?(\S+(?: bytes)?)\s+(\d+)$')


def find_cc(explicit):
    if explicit:
        return shlex.split(explicit)
    if os.environ.get('CC'):
        return shlex.split(os.environ['CC'])
    for name in ('gcc', 'clang'):
        if shutil.which(name):
            return [name]
    try:
        import ziglang  # noqa: F401
        return [sys.executable, '-m', 'ziglang', 'cc']
    except ImportError:
        raise SystemExit('no C compiler: pass --cc, set CC, install gcc/clang or pip install ziglang')


def generate(workdir):
    for name in ('bench.proto', 'bench.options', 'bench_validate_main.c'):
        shutil.copy(os.path.join(HERE, name), workdir)
    gen = os.path.join(ROOT, 'generator')
    cmd = [sys.executable, os.path.join(gen, 'protoc'), '-I.', '-I' + os.path.join(gen, 'proto'),
           '--nanopb_out=--protoc-insertion-points,-x,validate.proto:.',
           '--nanopb-validate_out=--filter=Envelope,-x,validate.proto:.', 'bench.proto']
    proc = subprocess.run(cmd, cwd=workdir, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          universal_newlines=True)
    if proc.returncode != 0:
        raise SystemExit('generation failed:\n' + proc.stdout)


def build_and_run(cc, workdir, name, flags, iterations):
    objdir = os.path.join(workdir, re.sub(r'\W+', '_', name))
    os.makedirs(objdir)
    sources = [os.path.join(workdir, f) for f in ('bench_validate_main.c', 'bench.pb.c', 'bench_validate.c')]
    sources += [os.path.join(ROOT, f) for f in ('pb_common.c', 'pb_encode.c', 'pb_decode.c', 'pb_validate.c')]
    objects = []
    for src in sources:
        obj = os.path.join(objdir, os.path.splitext(os.path.basename(src))[0] + '.o')
        cmd = cc + ['-std=c11', '-O2', '-Wall', '-I' + workdir, '-I' + ROOT] + flags + ['-c', src, '-o', obj]
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
        if proc.returncode != 0:
            raise SystemExit('%s: compile failed:\n%s' % (name, proc.stdout))
        objects.append(obj)
    exe = os.path.join(objdir, 'bench.exe')
    proc = subprocess.run(cc + ['-O2', '-o', exe] + objects, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          universal_newlines=True)
    if proc.returncode != 0:
        raise SystemExit('%s: link failed:\n%s' % (name, proc.stdout))
    proc = subprocess.run([exe, str(iterations)], stdout=subprocess.PIPE, universal_newlines=True)
    if proc.returncode != 0:
        raise SystemExit('%s: benchmark failed:\n%s' % (name, proc.stdout))
    times, sizes, stack = {}, {}, {}
    for line in proc.stdout.splitlines():
        m = TIME_RE.match(line)
        if m:
            times[(m.group(1), m.group(2))] = float(m.group(3))
            continue
        m = STACK_RE.match(line)
        if m:
            stack[m.group(1)] = int(m.group(2))
            continue
        m = SIZE_RE.match(line)
        if m:
            sizes[m.group(1)] = int(m.group(2))
    return times, sizes, stack


def main():
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('--iterations', type=int, default=50000)
    parser.add_argument('--cc', default=None, help='compiler command, e.g. "zig cc"')
    args = parser.parse_args()
    cc = find_cc(args.cc)
    workdir = tempfile.mkdtemp(prefix='nanopb_bench_')
    try:
        generate(workdir)
        rows = [(name,) + build_and_run(cc, workdir, name, flags, args.iterations) for name, flags in CONFIGS]
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    sizes = rows[0][2]
    print('Packet %d bytes; sizeof(Envelope) %d, sizeof(pb_violations_t) %d, sizeof(pb_validate_context_t) %d\n'
          % (sizes.get('packet bytes', 0), sizes.get('Envelope', 0), sizes.get('pb_violations_t', 0),
             sizes.get('pb_validate_context_t', 0)))
    print('ns per packet (best of 7 x %d iterations, -O2):\n' % args.iterations)
    header = ['configuration'] + ['%s %s' % (op, p) for op in OPERATIONS for p in PACKETS]
    print('| ' + ' | '.join(header) + ' |')
    print('|' + '---|' * len(header))
    for name, times, _, _ in rows:
        cells = ['%.0f' % times.get((op, p), 0) for op in OPERATIONS for p in PACKETS]
        print('| ' + ' | '.join([name] + cells) + ' |')
    print('\nPeak stack bytes per call on the valid packet (pb_decode and validators included):\n')
    print('| configuration | ' + ' | '.join(OPERATIONS) + ' |')
    print('|' + '---|' * (len(OPERATIONS) + 1))
    for name, _, _, stack in rows:
        print('| ' + ' | '.join([name] + [str(stack.get(op, '?')) for op in OPERATIONS]) + ' |')


if __name__ == '__main__':
    main()
