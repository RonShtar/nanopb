"""nanopb_validate: validation, packet filters and Wireshark tools for nanopb.

    python -m nanopb_validate check     PROTOS_DIR
    python -m nanopb_validate gen       PROTOS_DIR --out DIR      (or FILE.proto ...)
    python -m nanopb_validate packets   PROTOS_DIR --out DIR
    python -m nanopb_validate wireshark install|load|refresh|units|pick ...
    python -m nanopb_validate test      [--c] [--py] [--perf] [--security]

PROTOS_DIR holds one folder per protocol (its .proto files may sit in
subfolders). Run `python -m nanopb_validate COMMAND --help` for the options.
Commands on a directory print a JSON result; the Wireshark plugins read it.
nanopb itself is used read-only from the checkout this folder sits in.
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import env  # noqa: E402
from gen import include_format_opts  # noqa: E402

#: `wireshark` subcommands -> backend commands.
WIRESHARK = {
    'install': 'install-studio',      # plugins + project copy + protos directory, once
    'load': 'install-dissector',      # (re)load a protos directory into the dissector now
    'refresh': 'refresh-schema',      # rebuild the schema if protos changed (run at startup)
    'units': 'units',                 # list protocols and messages
    'pick': 'pick-units',             # tick-box window to choose protocols
}

USAGE = __doc__.split('\n\n')[1]


def backend_main(argv):
    import backend
    return backend.main(argv)


# ---------------------------------------------------------------------------
# gen
# ---------------------------------------------------------------------------

def gen_files(files, includes=(), out_dir='.', filters=(), protocol_filter=None, filter_name=None,
              nanopb_opts=(), validate_opts=(), validate=True, include_prefix=None):
    """Generate <file>.pb.c/.h and <file>_validate.c/.h for each .proto, in one protoc run.

    nanopb options (naming styles, -q, ...) go to both plugins, so the C names
    agree; validate.proto is never generated, only used.
    """

    shared = list(nanopb_opts) + ['-x', 'validate.proto'] + include_format_opts(include_prefix)
    own = list(validate_opts)
    if filters:
        own.append('--filter=' + ';'.join(filters))
    if protocol_filter:
        own.append('--protocol-filter=' + protocol_filter)
    if filter_name:
        own.append('--filter-name=' + filter_name)
    args = ['-I' + d for d in (list(includes) or ['.'])] + ['-I' + env.VALIDATE_PROTO_DIR]
    args.append('--nanopb_out=' + ','.join((['--protoc-insertion-points'] if validate else []) + shared) + ':' + out_dir)
    if validate:
        args.append('--nanopb-validate_out=' + ','.join(shared + own) + ':' + out_dir)
    args += list(files)
    status, output = env.run_protoc(args)
    if output:
        sys.stderr.write(output)
    return status


def files_parser():
    p = argparse.ArgumentParser(prog='nanopb_validate gen', description='Generate C for individual .proto files: '
                                '<name>.pb.c/.h (nanopb) and <name>_validate.c/.h, next to each other.')
    p.add_argument('inputs', nargs='+', metavar='FILE.proto')
    p.add_argument('-I', '--include', action='append', default=[], help='protoc include directory (default .)')
    p.add_argument('-D', '--out', default='.', help='output directory (default .)')
    p.add_argument('--filter', action='append', default=[], metavar='pkg.Msg',
                   help='also generate a packet filter with this entrypoint (repeatable)')
    p.add_argument('--protocol-filter', metavar='NAME', help='one Any-dispatched filter for every message')
    p.add_argument('--filter-name', metavar='NAME', help='entry points NAME_udp / NAME_tcp')
    p.add_argument('--nanopb-opt', action='append', default=[], metavar='OPT',
                   help='option for nanopb_generator (e.g. -q, -s, --c-style), passed to both plugins')
    p.add_argument('--validate-opt', action='append', default=[], metavar='OPT',
                   help='extra option for the validate plugin')
    p.add_argument('--no-validate', action='store_true', help='plain nanopb output only')
    p.add_argument('--include-prefix', metavar='DIR', help='include runtime headers as <DIR/pb.h> '
                   '(e.g. NanoPB); default <pb.h>')
    return p


def cmd_gen(argv, global_args):
    """gen FILE.proto ... -> per-file output; gen DIR / --protos-root DIR -> merged per protocol."""

    files = [a for a in argv if a.endswith('.proto') and not a.startswith('-')]
    if files and '--protos-root' not in argv:
        args = files_parser().parse_args(argv)
        return gen_files(args.inputs, args.include, args.out, args.filter, args.protocol_filter, args.filter_name,
                         args.nanopb_opt, args.validate_opt, not args.no_validate, args.include_prefix)
    return backend_main(global_args + ['gen-c'] + with_protos_root(argv))


def with_protos_root(argv):
    """Accept the protos directory as the first positional argument too."""

    if argv and not argv[0].startswith('-') and '--protos-root' not in argv:
        return ['--protos-root', argv[0]] + argv[1:]
    return argv


# ---------------------------------------------------------------------------
# check
# ---------------------------------------------------------------------------

def cmd_check(argv, global_args):
    """Compile every protocol of a protos directory and report what would go wrong.

    Errors: protoc syntax/import errors, validate rules the generator cannot
    honour. Warnings: fields without max_size/max_count (callbacks instead of
    static storage), messages that need PB_FIELD_32BIT, packet filters that
    cannot be generated.
    """

    p = argparse.ArgumentParser(prog='nanopb_validate check', description=cmd_check.__doc__.split('\n\n')[0])
    p.add_argument('protos_root', metavar='PROTOS_DIR')
    p.add_argument('-I', '--include', action='append', default=[])
    p.add_argument('--unit', default=None, help='comma-separated protocols (default: all)')
    args = p.parse_args(argv)

    import contextlib
    import io
    import backend

    out = tempfile.mkdtemp(prefix='nanopb_check_')
    report = {'protos_root': os.path.abspath(args.protos_root), 'protocols': [], 'errors': 0, 'warnings': 0}
    try:
        units_argv = global_args + ['units', '--protos-root', args.protos_root, '--names-only']
        names = run_json(backend.main, units_argv).get('units', [])
        if args.unit:
            names = [u.strip() for u in args.unit.split(',') if u.strip()]
        for name in names:
            entry = {'protocol': name, 'errors': [], 'warnings': []}
            gen_argv = global_args + ['gen-c', '--protos-root', args.protos_root, '--unit', name, '--out', out]
            for inc in args.include:
                gen_argv += ['-I', inc]
            buf_err = io.StringIO()
            with contextlib.redirect_stderr(buf_err):
                result = run_json(backend.main, gen_argv)
            if not result:
                entry['errors'] += [l.strip() for l in buf_err.getvalue().splitlines()
                                    if l.strip() and 'is unused' not in l][-12:]
            for unit in result.get('units', []):
                entry['warnings'] += check_generated(unit)
            report['errors'] += len(entry['errors'])
            report['warnings'] += len(entry['warnings'])
            report['protocols'].append(entry)
    finally:
        import shutil
        shutil.rmtree(out, ignore_errors=True)

    lines = []
    for entry in report['protocols']:
        state = 'ERROR' if entry['errors'] else ('warn' if entry['warnings'] else 'ok')
        lines.append('%-5s %s' % (state, entry['protocol']))
        lines += ['      error: ' + e for e in entry['errors']]
        lines += ['      ' + w for w in entry['warnings']]
    lines.append('%d protocol(s), %d error(s), %d warning(s)'
                 % (len(report['protocols']), report['errors'], report['warnings']))
    report['summary'] = '\n'.join(lines)
    print(json.dumps(report, indent=2))
    print('__EXIT__=%d' % (1 if report['errors'] else 0))
    return 1 if report['errors'] else 0


def check_generated(unit):
    """Warnings for one gen-c result."""

    warnings = []
    header = os.path.join(unit['dir'], unit['unit'] + '.pb.h')
    if os.path.isfile(header):
        with open(header, encoding='utf-8', errors='replace') as handle:
            text = handle.read()
        callbacks = sorted(set(l.split('pb_callback_t')[1].strip(' ;') for l in text.splitlines()
                               if 'pb_callback_t ' in l and not l.lstrip().startswith(('*', '/'))))
        if callbacks:
            warnings.append('fields without max_size/max_count use callbacks, not static storage: '
                            + ', '.join(callbacks))
    for reason in unit.get('needs_field_32bit') or []:
        warnings.append('needs PB_FIELD_32BIT: ' + reason)
    if unit.get('protocol_filter_error') and 'does not use google.protobuf.Any' not in unit['protocol_filter_error']:
        warnings.append('no protocol filter: ' + unit['protocol_filter_error'].splitlines()[0])
    for message, error in sorted((unit.get('filter_errors') or {}).items()):
        warnings.append('no filter for %s: %s' % (message, error.splitlines()[0]))
    return warnings


def run_json(func, argv):
    """Run a backend command in-process and return its JSON result ({} on failure)."""

    import contextlib
    import io
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        status = func(argv)
    text = out.getvalue().rstrip()
    marker = '__EXIT__=%d' % status
    if status != 0 or not text.endswith(marker):
        return {}
    body = text[:-len(marker)].strip()
    return json.loads(body) if body else {}


# ---------------------------------------------------------------------------
# test
# ---------------------------------------------------------------------------

def cmd_test(argv, global_args):
    p = argparse.ArgumentParser(prog='nanopb_validate test',
                                description='Run the tool\'s tests (default: Python tests and C tests).')
    p.add_argument('--py', action='store_true', help='Python tests (tool, dissector, security, performance)')
    p.add_argument('--c', action='store_true', help='C tests of the runtime and generated code (SCons)')
    p.add_argument('--perf', action='store_true', help='only the performance budgets')
    p.add_argument('--security', action='store_true', help='only the security fuzz tests')
    p.add_argument('scons_args', nargs='*', help='extra SCons arguments for --c, e.g. TOOLS=mingw CC=clang')
    args = p.parse_args(argv)
    tests_dir = os.path.join(env.VALIDATE_DIR, 'tests')
    status = 0
    pattern = 'test_performance.py' if args.perf else ('test_security.py' if args.security else None)
    run_py = args.py or pattern or not args.c
    run_c = args.c or not (args.py or pattern)
    if run_py:
        cmd = [sys.executable, '-m', 'unittest', 'discover', '-s', os.path.join(tests_dir, 'py')]
        if pattern:
            cmd += ['-p', pattern]
        status |= subprocess.call(cmd)
    if run_c:
        status |= subprocess.call([sys.executable, '-m', 'SCons'] + args.scons_args, cwd=os.path.join(tests_dir, 'c'))
    return 1 if status else 0


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    global_args = []
    while argv and argv[0] == '--nanopb-root' and len(argv) > 1:
        global_args += argv[:2]
        env.set_nanopb_root(argv[1])
        argv = argv[2:]
    if not argv or argv[0] in ('-h', '--help'):
        print(__doc__)
        return 0 if argv else 1
    command, rest = argv[0], argv[1:]
    try:
        env.setup()
    except RuntimeError as exc:
        sys.stderr.write('error: %s\n' % exc)
        return 1
    if command == 'gen':
        return cmd_gen(rest, global_args)
    if command == 'check':
        return cmd_check(rest, global_args)
    if command == 'packets':
        return backend_main(global_args + ['gen-packets'] + with_protos_root(rest))
    if command == 'wireshark':
        if not rest or rest[0] not in WIRESHARK:
            sys.stderr.write('usage: nanopb_validate wireshark {%s} ...\n' % ','.join(WIRESHARK))
            return 1
        return backend_main(global_args + [WIRESHARK[rest[0]]] + rest[1:])
    if command == 'test':
        return cmd_test(rest, global_args)
    sys.stderr.write('unknown command %r\n\n%s\n' % (command, USAGE))
    return 1


if __name__ == '__main__':
    sys.exit(main())
