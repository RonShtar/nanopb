"""Protocols of a protos directory: finding units (also in nested folders), compiling
their descriptors, entry points, and helpers shared by the other modules.
"""

import os
import re
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import env  # noqa: E402


# .options for google/protobuf/any.proto (static storage for Any).
DEFAULT_INCLUDE = os.path.join(env.PKG_DIR, 'wireshark_include')

# Files that are only used for generator options and never generated.
OPTION_PROTOS = ('validate.proto', 'nanopb.proto')

RUNTIME_FILES = ('pb.h', 'pb_common.h', 'pb_common.c', 'pb_encode.h', 'pb_encode.c',
                 'pb_decode.h', 'pb_decode.c')
VALIDATE_RUNTIME_FILES = ('pb_validate.h', 'pb_validate.c', 'pb_filter_macros.h')

INCLUDE_RE = re.compile(r'^\s*#\s*include\s+"([^"]+)"\s*$')


class BackendError(Exception):
    pass


# ---------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------

def setup_nanopb(nanopb_root):
    """Use the nanopb checkout at ``nanopb_root`` (read-only) and build the _pb2 modules."""

    env.set_nanopb_root(nanopb_root)
    try:
        env.setup()
    except RuntimeError as exc:
        raise BackendError(str(exc))
    return env.GENERATOR_DIR


def is_option_proto(name):
    """True for a file that only defines generator options, in any folder."""

    return name == 'google/protobuf/descriptor.proto' or name.rsplit('/', 1)[-1] in OPTION_PROTOS


def find_units(protos_root):
    """Units of a protos directory: its subfolders that hold protos, directly
    or in folders of their own (protocol/enums/*.proto, protocol/messages/...).

    Vendored dependencies (google/, or a folder with only validate.proto or
    nanopb.proto) are not units. With no unit subfolder, a directory that
    holds .proto files itself is the one unit, named after the directory.
    """

    if not os.path.isdir(protos_root):
        raise BackendError('protos root %s is not a directory' % protos_root)
    units = []
    for name in sorted(os.listdir(protos_root)):
        path = os.path.join(protos_root, name)
        if not skipped_folder(name) and os.path.isdir(path) and all_unit_protos(path):
            units.append(name)
    if not units and unit_protos(protos_root):
        return [os.path.basename(os.path.abspath(protos_root))]
    return units


def skipped_folder(name):
    """Folders that never hold a unit's own protos: vendored google/, hidden ones."""

    return name == 'google' or name.startswith('.')


def unit_protos(unit_dir):
    """The unit's .proto files directly in ``unit_dir``."""

    return sorted(f for f in os.listdir(unit_dir)
                  if f.endswith('.proto') and os.path.isfile(os.path.join(unit_dir, f))
                  and not is_option_proto(f))


def unit_subfolders(unit_dir):
    """Every folder below ``unit_dir`` (absolute paths, parents first), without skipped ones."""

    result = []
    for root, dirs, _ in os.walk(unit_dir):
        dirs[:] = sorted(d for d in dirs if not skipped_folder(d))
        result += [os.path.join(root, d) for d in dirs]
    return result


def all_unit_protos(unit_dir):
    """The unit's .proto files in ``unit_dir`` and its subfolders, as '/'-separated
    paths relative to ``unit_dir``."""

    result = list(unit_protos(unit_dir))
    for folder in unit_subfolders(unit_dir):
        rel = os.path.relpath(folder, unit_dir).replace(os.sep, '/')
        result += [rel + '/' + f for f in unit_protos(folder)]
    return sorted(result)


def unit_folder(protos_root, name):
    """The folder of unit ``name``: a subfolder, or the root if it is the unit."""

    path = os.path.join(protos_root, name)
    return path if os.path.isdir(path) and all_unit_protos(path) else protos_root


def no_units_message(protos_root):
    return ('no .proto files found in %s or directly in its subfolders; '
            'enter the folder that holds your .proto files' % protos_root)


def select_units(args):
    all_units = find_units(args.protos_root)
    if not args.unit:
        if not all_units:
            raise BackendError(no_units_message(args.protos_root))
        return all_units
    wanted = [u.strip() for u in args.unit.split(',') if u.strip()]
    missing = [u for u in wanted if u not in all_units]
    if missing:
        raise BackendError('unknown unit(s) %s; available: %s'
                           % (', '.join(missing), ', '.join(all_units) or '(none)'))
    return wanted


def c_identifier(name):
    ident = re.sub(r'[^0-9A-Za-z_]', '_', name)
    if ident[:1].isdigit():
        ident = '_' + ident
    return ident


# ---------------------------------------------------------------------------
# Descriptors
# ---------------------------------------------------------------------------

def compile_descriptor_set(proto_names, include_paths):
    """Compile ``proto_names`` (virtual paths) to a FileDescriptorSet."""

    from nanopb_api import invoke_protoc
    from google.protobuf import descriptor_pb2

    tmpdir = tempfile.mkdtemp(prefix='nanopb_ws_')
    try:
        out = os.path.join(tmpdir, 'set.pb')
        argv = ['protoc', '--include_imports', '--descriptor_set_out=' + out]
        argv += ['-I' + p for p in include_paths if os.path.isdir(p)]
        argv += list(proto_names)
        status = invoke_protoc(argv)
        if status != 0:
            raise BackendError('protoc failed (status %s) for %s' % (status, ' '.join(proto_names)))
        fds = descriptor_pb2.FileDescriptorSet()
        with open(out, 'rb') as handle:
            fds.ParseFromString(handle.read())
        return fds
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def nested_layout(unit_dir, parent, protos):
    """(include folders, protoc names) of a unit whose protos sit in subfolders.

    An import names a file relative to some folder: the unit folder
    ("enums/types.proto"), the protos root ("unit/enums/types.proto"), or
    a subfolder such as the importing file's own ("types.proto"). Every
    folder an import needs becomes an include path, and each proto gets the
    name its importers use, so protoc loads no file twice. Protos nobody
    imports are named relative to the unit folder.
    """

    def key(path):
        return os.path.normcase(os.path.abspath(path))

    paths = dict((p, key(os.path.join(unit_dir, p))) for p in protos)
    owner = dict((v, k) for k, v in paths.items())
    subfolders = unit_subfolders(unit_dir)
    imported_as, roots = {}, []
    for proto in protos:
        here = os.path.normpath(os.path.dirname(os.path.join(unit_dir, proto)))
        with open(os.path.join(unit_dir, proto), encoding='utf-8', errors='replace') as handle:
            imports = IMPORT_RE.findall(handle.read())
        for imp in imports:
            if imp.startswith('google/protobuf/'):
                continue
            for root in [here, unit_dir, parent] + subfolders:
                target = key(os.path.join(root, imp))
                if os.path.isfile(target):
                    break
            else:
                continue  # found through -I or the default include path, if at all
            if target in owner:
                previous = imported_as.setdefault(target, imp)
                if previous != imp:
                    raise BackendError('%s is imported both as "%s" and as "%s"; protoc needs one '
                                       'name per file, use the same import path everywhere'
                                       % (owner[target], previous, imp))
            if key(root) not in [key(r) for r in [unit_dir, parent] + roots]:
                roots.append(root)
    includes = [unit_dir] + roots + [parent]
    names = [imported_as.get(paths[p], p) for p in protos]
    # protoc finds a name in the first include folder that has it.
    for proto, name in zip(protos, names):
        found = next((key(os.path.join(r, name)) for r in includes
                      if os.path.isfile(os.path.join(r, name))), None)
        if found != paths[proto]:
            raise BackendError('import "%s" is ambiguous: %s and %s both match; rename one of them '
                               'or import it with its folder ("folder/%s")'
                               % (name, proto, os.path.relpath(found, unit_dir) if found else '?',
                                  os.path.basename(name)))
    return includes, names


class Unit(object):
    """One protos-root subdirectory, resolved to protoc virtual names."""

    def __init__(self, protos_root, name, extra_includes):
        self.name = name
        self.dir = unit_folder(protos_root, name)
        direct = unit_protos(self.dir)
        nested = all_unit_protos(self.dir)
        parent = os.path.dirname(self.dir)
        candidates = []
        if direct:
            candidates += [
                # Imports relative to the unit directory: import "foo.proto";
                (direct, [self.dir, parent], direct),
                # Imports relative to the protos root: import "unit/foo.proto";
                (direct, [parent, self.dir], [name + '/' + p for p in direct]),
            ]
        errors = []
        if len(nested) > len(direct):
            # Protos in subfolders (unit/enums/a.proto, unit/infra/messages/b.proto):
            # their import lines say which folders are include paths.
            try:
                candidates.append((nested,) + nested_layout(self.dir, parent, nested))
            except BackendError as exc:
                errors.append(str(exc))
        for protos, roots, names in candidates:
            includes = roots + list(extra_includes) + [DEFAULT_INCLUDE, env.VALIDATE_PROTO_DIR]
            try:
                self.fds = compile_descriptor_set(names, includes)
            except BackendError as exc:
                errors.append(str(exc))
                continue
            self.protos = protos
            self.includes = includes
            self.names = names
            break
        else:
            raise BackendError('could not compile unit %s:\n  %s' % (name, '\n  '.join(errors)))

    def generated_files(self):
        """Descriptor file names to generate, dependencies first."""

        return [f.name for f in self.fds.file if not is_option_proto(f.name)]

    def messages(self):
        result = []
        for fdesc in self.fds.file:
            if fdesc.name not in self.names:
                continue
            for msg in fdesc.message_type:
                result.append((fdesc.package + '.' if fdesc.package else '') + msg.name)
        return result


# ---------------------------------------------------------------------------
# gen-c
# ---------------------------------------------------------------------------

def field_rules(field):
    """The (validate.rules) option of a FieldDescriptorProto, or None."""

    from google.protobuf import descriptor_pb2
    from datagen import _load_validate_pb2

    validate_pb2 = _load_validate_pb2()
    # The descriptor set was parsed before the extension was known; parse the
    # options again so the extension is resolved.
    options = descriptor_pb2.FieldOptions.FromString(field.options.SerializeToString())
    if options.HasExtension(validate_pb2.rules):
        return options.Extensions[validate_pb2.rules]
    return None


def unit_entrypoints(unit, port_map):
    """Messages of the unit that get a packet filter, and where they came from.

    Port map entries are the protocol entrypoints the dissector uses. Without
    any for this unit, the roots are the unit's top-level messages that no
    other message of the unit uses as a field type or Any payload.
    """

    own = unit.messages()
    mapped = [msg for _, _, msg in parse_port_map(port_map, None) if msg in own]
    if mapped:
        return sorted(set(mapped), key=mapped.index), 'port map'

    referenced = set()

    def walk(msg):
        for fld in msg.field:
            if fld.type == 11:  # TYPE_MESSAGE
                referenced.add(fld.type_name.lstrip('.'))
            rules = field_rules(fld)
            if rules is not None and rules.HasField('any'):
                for item in getattr(rules.any, 'in'):
                    referenced.add(item.rsplit('/', 1)[-1].lstrip('.'))
        for nested in msg.nested_type:
            walk(nested)

    for fdesc in unit.fds.file:
        if fdesc.name in unit.names:
            for msg in fdesc.message_type:
                walk(msg)
    return [m for m in own if m not in referenced], 'auto'


def protocol_name(unit):
    """C name of the unit's protocol filter, or None if the unit never uses Any."""

    if not any(f.name == 'google/protobuf/any.proto' for f in unit.fds.file):
        return None
    return c_identifier(unit.name)


def unit_root(unit):
    """The one message a unit's packets can be without an Any around them, or None."""

    roots, _ = unit_entrypoints(unit, None)
    return roots[0] if len(roots) == 1 else None


def protocol_messages(unit):
    """Messages a protocol accepts as Any payload: every message of the unit's
    compiled files (imports included) except map entries and google.protobuf.*,
    as nanopb-validate --protocol-filter does."""

    result = []

    def walk(prefix, msgs):
        for msg in msgs:
            fqn = prefix + msg.name
            if not msg.options.map_entry and not fqn.startswith('google.protobuf.'):
                result.append(fqn)
            walk(fqn + '.', msg.nested_type)

    for fdesc in unit.fds.file:
        if not is_option_proto(fdesc.name):
            walk(fdesc.package + '.' if fdesc.package else '', fdesc.message_type)
    return result


def unit_data_generator(unit, DataGenerator):
    """A DataGenerator that sees every message of the unit at once.

    DataGenerator loads one .proto and its imports; Any rules may name types
    from files that file doesn't import, so load a throwaway proto that
    imports the whole unit.
    """

    tmpdir = tempfile.mkdtemp(prefix='nanopb_ws_unit_')
    try:
        path = os.path.join(tmpdir, 'nanopb_ws_unit_all.proto')
        with open(path, 'w', newline='\n') as handle:
            handle.write('syntax = "proto3";\n')
            for name in unit.names:
                handle.write('import "%s";\n' % name)
        return DataGenerator(path, [p for p in unit.includes if os.path.isdir(p)])
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def parse_port_map(text, messages):
    entries = []
    for item in re.split(r'[,;\s]+', text or ''):
        if not item:
            continue
        match = re.match(r'^(udp|tcp):(\d+)=([\w.]+)$', item, re.IGNORECASE)
        if not match:
            raise BackendError('bad port map entry %r (expected udp:5000=pkg.Message)' % item)
        msg = match.group(3)
        if messages is not None and msg not in messages:
            raise BackendError('port map message %s is not in the schema' % msg)
        entries.append((match.group(1).lower(), int(match.group(2)), msg))
    return entries


IMPORT_RE = re.compile(r'^\s*import\s+(?:public\s+|weak\s+)?"([^"]+)"', re.M)


def merged_into(protos_root, units):
    """{unit: [units that import it]}: their merged .c/.h already contain it.

    Found by scanning import lines, so it needs no protoc run.
    """

    result = {}
    for name in units:
        folder = unit_folder(protos_root, name)
        for proto in all_unit_protos(folder):
            with open(os.path.join(folder, proto), encoding='utf-8', errors='replace') as handle:
                for path in IMPORT_RE.findall(handle.read()):
                    other = path.split('/', 1)[0]
                    if '/' in path and other != name and other in units and name not in result.get(other, []):
                        result.setdefault(other, []).append(name)
    return result
