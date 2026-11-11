"""Everything this tool uses from nanopb's generator, in one place.

nanopb is used read-only from the checkout this folder sits in. Upgrading it
is a merge of nanopb's own files only; if a new nanopb version renames or
removes something listed here, `check()` (run by `python -m nanopb_validate
check` and by tests/py/test_nanopb_api.py) names it, and the fix goes in this
file, never in nanopb.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import env  # noqa: E402

env.setup()

import nanopb_generator  # noqa: E402  nanopb's generator/nanopb_generator.py
import proto  # noqa: E402  nanopb's generator/proto package
from proto import _utils as proto_utils  # noqa: E402

#: (module, attribute) pairs the tool relies on.
REQUIRED = [
    (nanopb_generator, 'Globals'),
    (nanopb_generator, 'OneOf'),
    (nanopb_generator, 'parse_file'),
    (nanopb_generator, 'process_cmdline'),
    (nanopb_generator, 'optparser'),
    (nanopb_generator, 'plugin_pb2'),
    (nanopb_generator, 'descriptor'),
    (proto, 'load_nanopb_pb2'),
    (proto, 'TemporaryDirectory'),
    (proto_utils, 'invoke_protoc'),
]

#: nanopb_generator options the tool passes to nanopb (both plugins).
REQUIRED_OPTIONS = ['-x', '-L', '-q', '-s', '--protoc-insertion-points', '--source-extension', '--header-extension']

#: Files of the nanopb checkout the tool runs or includes.
REQUIRED_FILES = ['generator/protoc', 'generator/protoc-gen-nanopb', 'generator/protoc-gen-nanopb.bat',
                  'generator/proto/nanopb.proto', 'pb.h', 'pb_common.c', 'pb_decode.c', 'pb_encode.c',
                  'tests/site_scons/site_init.py', 'tests/site_scons/site_tools/nanopb.py']

# The names the rest of the package uses (import nanopb_api as nanopb).
Globals = nanopb_generator.Globals
OneOf = nanopb_generator.OneOf
parse_file = nanopb_generator.parse_file
process_cmdline = nanopb_generator.process_cmdline
optparser = nanopb_generator.optparser
plugin_pb2 = nanopb_generator.plugin_pb2
descriptor = nanopb_generator.descriptor
invoke_protoc = proto_utils.invoke_protoc
TemporaryDirectory = proto.TemporaryDirectory
nanopb_pb2 = proto.load_nanopb_pb2()


def check():
    """Problems with the nanopb checkout this tool would run against ([] when all is well)."""

    problems = []
    for module, name in REQUIRED:
        if not hasattr(module, name):
            problems.append('nanopb: %s.%s is missing' % (module.__name__, name))
    known = set()
    for option in nanopb_generator.optparser.option_list:
        known.update(option._short_opts + option._long_opts)
    problems += ['nanopb_generator has no option %s' % o for o in REQUIRED_OPTIONS if o not in known]
    problems += ['nanopb checkout has no %s' % f for f in REQUIRED_FILES
                 if not os.path.isfile(os.path.join(env.NANOPB_ROOT, *f.split('/')))]
    naming = getattr(getattr(nanopb_generator, 'Globals', None), 'naming_style', None)
    for method in ('type_name', 'var_name', 'func_name', 'define_name'):
        if naming is not None and not hasattr(naming, method):
            problems.append('nanopb: Globals.naming_style.%s is missing' % method)
    return problems
