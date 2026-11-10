'''SCons tool: nanopb's NanopbProto builder, plus the nanopb-validate plugin.

Load after nanopb's own tool (tests/site_scons/site_tools/nanopb.py):

    env.Tool('nanopb')
    env.Tool('nanopb_validate')

NANOPB_VALIDATE_FLAGS = None (default) runs plain nanopb. Set it to a
(possibly empty) option string, e.g. '--filter=pkg.Envelope', to also write
<name>_validate.c/.h and inject the packet filter into <name>.pb.c/.h. nanopb
then emits insertion points, runs first, and NANOPBFLAGS reach both plugins
so the C names agree.
'''

import os.path

import SCons.Action
import SCons.Builder

import nanopb as nanopb_tool  # nanopb's tool module, for its emitter


def _plugin(env):
    name = 'protoc-gen-nanopb-validate' + ('.bat' if env['PLATFORM'] == 'win32' else '')
    return os.path.join(env['VALIDATE'], 'nanopb_validate', 'plugin', name)


def _actions(source, target, env, for_signature):
    esc = env['ESCAPE']
    prefix = os.path.dirname(str(source[-1]))
    srcfile = esc(os.path.relpath(str(source[0]), prefix))
    include_dirs = '-I.'
    for d in env['PROTOCPATH']:
        d = env.GetBuildPath(d)
        if not os.path.isabs(d):
            d = os.path.relpath(d, prefix)
        include_dirs += ' -I' + esc(d)

    source_extension = os.path.splitext(str(target[0]))[1]
    header_extension = '.h' + source_extension[2:]
    extensions = '--source-extension=%s,--header-extension=%s' % (source_extension, header_extension)
    validate_flags = env.get('NANOPB_VALIDATE_FLAGS')
    nanopb_flags = env['NANOPBFLAGS']

    insertion = ['--protoc-insertion-points'] if validate_flags is not None else []
    cmd = '$PROTOC $PROTOCFLAGS %s "--nanopb_out=%s:."' % (
        include_dirs, ','.join(filter(None, [extensions] + insertion + [nanopb_flags])))
    if validate_flags is not None:
        cmd += ' %s "--nanopb-validate_out=%s:."' % (
            esc('--plugin=protoc-gen-nanopb-validate=' + _plugin(env)),
            ','.join(filter(None, [extensions, validate_flags, nanopb_flags])))
    return SCons.Action.CommandAction('%s %s' % (cmd, srcfile), chdir=prefix)


def generate(env):
    env.SetDefault(NANOPB_VALIDATE_FLAGS=None)
    builder = dict(generator=_actions, src_suffix='.proto', emitter=nanopb_tool._nanopb_proto_emitter)
    env['BUILDERS']['NanopbProto'] = SCons.Builder.Builder(suffix='.pb.c', **builder)
    env['BUILDERS']['NanopbProtoCpp'] = SCons.Builder.Builder(suffix='.pb.cpp', **builder)


def exists(env):
    return True
