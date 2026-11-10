"""Where things are, and the one-time setup every entry point runs first.

nanopb itself (the checkout this folder sits in) is used read-only: its
generator/ directory goes on sys.path so nanopb_generator and its `proto`
package import as usual, and nothing of ours is written into it.
validate.proto and its generated validate_pb2.py live in validate_proto/ next
to this file.
"""

import os
import subprocess
import sys

PKG_DIR = os.path.dirname(os.path.abspath(__file__))
VALIDATE_DIR = os.path.dirname(PKG_DIR)
NANOPB_ROOT = os.path.dirname(VALIDATE_DIR)
GENERATOR_DIR = os.path.join(NANOPB_ROOT, 'generator')
NANOPB_PROTO_DIR = os.path.join(GENERATOR_DIR, 'proto')
VALIDATE_PROTO_DIR = os.path.join(PKG_DIR, 'validate_proto')
RUNTIME_DIR = os.path.join(VALIDATE_DIR, 'runtime')
PLUGIN_DIR = os.path.join(PKG_DIR, 'plugin')

_ready = False


def set_nanopb_root(root):
    """Use another nanopb checkout's generator (tests, or a copied project)."""

    global NANOPB_ROOT, GENERATOR_DIR, NANOPB_PROTO_DIR
    NANOPB_ROOT = os.path.abspath(root)
    GENERATOR_DIR = os.path.join(NANOPB_ROOT, 'generator')
    NANOPB_PROTO_DIR = os.path.join(GENERATOR_DIR, 'proto')


def protoc_include_dirs():
    """-I directories that make nanopb.proto and validate.proto importable."""

    return [NANOPB_PROTO_DIR, VALIDATE_PROTO_DIR]


def setup():
    """Make nanopb_generator, nanopb_pb2 and validate_pb2 importable. Idempotent.

    Both _pb2 modules are built here, before any protoc run, so a protoc plugin
    never has to build them itself (which would print protoc's version into
    the plugin's reply).
    """

    global _ready
    if _ready:
        return
    if not os.path.isfile(os.path.join(GENERATOR_DIR, 'nanopb_generator.py')):
        raise RuntimeError('%s does not look like a nanopb checkout (no generator/nanopb_generator.py)'
                           % NANOPB_ROOT)
    for path in (PKG_DIR, GENERATOR_DIR, VALIDATE_PROTO_DIR):
        if path not in sys.path:
            sys.path.insert(0, path)
    import proto  # nanopb's generator/proto package
    proto.load_nanopb_pb2()
    build_validate_pb2()
    _ready = True


def build_validate_pb2():
    """validate_proto/validate_pb2.py from validate.proto, if missing or stale."""

    source = os.path.join(VALIDATE_PROTO_DIR, 'validate.proto')
    target = os.path.join(VALIDATE_PROTO_DIR, 'validate_pb2.py')
    if os.path.isfile(target) and os.path.getmtime(target) >= os.path.getmtime(source):
        return
    from grpc_tools import protoc as grpc_protoc
    import grpc_tools
    well_known = os.path.join(os.path.dirname(grpc_tools.__file__), '_proto')
    args = ['protoc', '-I' + VALIDATE_PROTO_DIR, '-I' + well_known, '--python_out=' + VALIDATE_PROTO_DIR,
            '--experimental_allow_proto3_optional', source]
    # protoc prints nothing on success; keep stdout clean for plugin callers anyway.
    sys.stdout.flush()
    saved = os.dup(1)
    os.dup2(2, 1)
    try:
        status = grpc_protoc.main(args)
    finally:
        os.dup2(saved, 1)
        os.close(saved)
    if status != 0:
        raise RuntimeError('protoc failed (%s) building %s' % (status, target))


def plugin_path():
    """protoc-gen-nanopb-validate launcher for this platform."""

    name = 'protoc-gen-nanopb-validate' + ('.bat' if os.name == 'nt' else '')
    return os.path.join(PLUGIN_DIR, name)


def protoc_command():
    """argv prefix running nanopb's own protoc wrapper with our plugin registered.

    nanopb's generator/protoc registers protoc-gen-nanopb and nanopb.proto;
    we add protoc-gen-nanopb-validate. Callers add -I VALIDATE_PROTO_DIR (for
    validate.proto) with their other include paths. Pass --nanopb_out before
    --nanopb-validate_out: the validate plugin inserts into nanopb's files.
    """

    return [sys.executable, os.path.join(GENERATOR_DIR, 'protoc'),
            '--plugin=protoc-gen-nanopb-validate=' + plugin_path()]


def subprocess_env():
    """Environment for protoc's plugins: on Windows the .bat launchers start
    `python` from PATH, which must be this Python (the one with protobuf)."""

    env = dict(os.environ)
    env['PATH'] = os.path.dirname(sys.executable) + os.pathsep + env.get('PATH', '')
    extra = os.pathsep.join([PKG_DIR, GENERATOR_DIR, VALIDATE_PROTO_DIR])
    env['PYTHONPATH'] = extra + (os.pathsep + env['PYTHONPATH'] if env.get('PYTHONPATH') else '')
    return env


def run_protoc(args, cwd=None):
    """Run protoc (with both plugins available); returns (status, output)."""

    setup()
    proc = subprocess.run(protoc_command() + list(args), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          universal_newlines=True, cwd=cwd, env=subprocess_env())
    return proc.returncode, proc.stdout
