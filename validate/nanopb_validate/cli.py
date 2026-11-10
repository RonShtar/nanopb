"""nanopb_validate: validation, packet filters and Wireshark tools for nanopb.

    python -m nanopb_validate gen  FILE.proto ... [--filter pkg.Msg] [-I DIR] [-D OUT]

Run from validate/ (or with validate/ on PYTHONPATH). nanopb itself is used
read-only from the checkout this folder sits in.
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import env  # noqa: E402


def gen_files(files, includes=(), out_dir='.', filters=(), protocol_filter=None, filter_name=None,
              nanopb_opts=(), validate_opts=(), validate=True):
    """Generate <file>.pb.c/.h and <file>_validate.c/.h for each .proto, in one protoc run.

    nanopb options (naming styles, -q, ...) go to both plugins, so the C names
    agree; validate.proto is never generated, only used.
    """

    shared = list(nanopb_opts) + ['-x', 'validate.proto']
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


def build_parser():
    parser = argparse.ArgumentParser(prog='nanopb_validate', description=__doc__.split('\n\n')[0])
    sub = parser.add_subparsers(dest='command', metavar='COMMAND')
    sub.required = True

    p = sub.add_parser('gen', help='generate C (nanopb + validators + packet filters)')
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
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        env.setup()
    except RuntimeError as exc:
        sys.stderr.write('error: %s\n' % exc)
        return 1
    if args.command == 'gen':
        return gen_files(args.inputs, args.include, args.out, args.filter, args.protocol_filter, args.filter_name,
                         args.nanopb_opt, args.validate_opt, not args.no_validate)
    return 1


if __name__ == '__main__':
    sys.exit(main())
