"""The Wireshark side: dissector schema (Lua), installing and refreshing it, the
studio install, protocol listing and the tick-box picker.
"""

import json
import os
import re
import shutil
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import env  # noqa: E402
from protos import (BackendError, DEFAULT_INCLUDE, RUNTIME_FILES, Unit, c_identifier, compile_descriptor_set,  # noqa: E402
                    field_rules, find_units, is_option_proto, merged_into, no_units_message, parse_port_map,
                    protocol_messages, unit_data_generator, unit_root)


TOOL_DIR = os.path.join(env.VALIDATE_DIR, 'wireshark')


# ---------------------------------------------------------------------------
# schema / install
# ---------------------------------------------------------------------------

def lua_str(value):
    return '"' + value.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n') + '"'


# Field types whose values the dissector compares as 64-bit keys (True = signed).
INT64_TYPES = {3: True, 16: True, 18: True, 4: False, 6: False}  # INT64, SFIXED64, SINT64; UINT64, FIXED64

# Rule kinds nanopb-validate has no C emitter for: generating C code fails on
# them, so they never reject a packet. The dissector lists them as not checked.
UNSUPPORTED_KINDS = ('ONEOF_REQUIRED', 'NO_SPARSE')
UNSUPPORTED_OPTIONS = ('pattern', 'min_bytes', 'max_bytes')


def int64_key(value, signed):
    """Order-preserving 16-digit hex key of a 64-bit integer (signed: offset by 2^63)."""

    value = int(value)
    if signed:
        value += 1 << 63
    return '%016x' % (value & ((1 << 64) - 1))


VALUE_KINDS = ('GT', 'GTE', 'LT', 'LTE', 'EQ', 'IN', 'NOT_IN')


def rule_entry(rule_id, kind, params, field_type):
    entry = {'id': rule_id, 'kind': kind}
    # Only comparisons with the field's value use 64-bit keys, not counts or lengths.
    wide = field_type in INT64_TYPES and kind in VALUE_KINDS

    def scalar(value):
        if wide and isinstance(value, int) and not isinstance(value, bool):
            return int64_key(value, INT64_TYPES[field_type])
        return value

    if 'value' in params:
        entry['key' if wide and not isinstance(params['value'], bool) else 'v'] = scalar(params['value'])
    if 'values' in params:
        entry['keys' if wide else 'list'] = [scalar(v) for v in params['values']]
    if 'seconds' in params:
        entry['seconds'] = int(params['seconds'])
    if 'item_rules' in params:
        entry['items'] = [rule_entry(i.get('constraint_id', ''), i.get('rule'), i, field_type)
                          for i in params['item_rules']]
    if kind in UNSUPPORTED_KINDS:
        entry['kind'] = 'UNSUPPORTED'
    return entry


def field_rule_entries(field, rules_option=None):
    """The field's validate.proto rules as dissector rule entries.

    rules_option overrides the field's own (validate.rules), e.g. the
    map.keys / map.values rules applied to a map entry's key and value.
    map.keys / map.values themselves are not listed here: build_schema puts
    them on the fields of the map's *Entry message.
    """

    import validator as nanopb_validator

    if rules_option is None:
        rules_option = field_rules(field)
    if rules_option is None:
        return []
    option = type(rules_option)()
    option.CopyFrom(rules_option)
    entries = []
    for kind in ('string', 'bytes'):
        if option.HasField(kind):
            sub = getattr(option, kind)
            for name in UNSUPPORTED_OPTIONS:
                if name in sub.DESCRIPTOR.fields_by_name and sub.HasField(name):
                    entries.append({'id': '%s.%s' % (kind, name), 'kind': 'UNSUPPORTED'})
                    sub.ClearField(name)
    rules = nanopb_validator.FieldValidator(field, option).rules
    return [rule_entry(r.constraint_id, r.rule_type, r.params, field.type) for r in rules
            if r.rule_type != nanopb_validator.RULE_MAP_ENTRIES] + entries


def add_map_entry_rules(msg, messages):
    """Put a map field's map.keys / map.values rules on its *Entry message's
    key and value fields, so the dissector checks them on every entry (the
    paths, e.g. counts[1].key, match the C validator's)."""

    nested = dict((n.name, n) for n in msg.nested_type)
    for fld in msg.field:
        rules_option = field_rules(fld)
        if rules_option is None or not rules_option.HasField('map'):
            continue
        entry_desc = nested.get(fld.type_name.rsplit('.', 1)[-1])
        entry = messages.get(fld.type_name.lstrip('.'))
        if entry_desc is None or entry is None or not entry_desc.options.map_entry:
            continue
        entry_fields = entry['fields']
        for sub in entry_desc.field:
            part = {'key': 'keys', 'value': 'values'}.get(sub.name)
            if part and rules_option.map.HasField(part):
                rules = field_rule_entries(sub, getattr(rules_option.map, part))
                if rules:
                    entry_fields[sub.number].setdefault('rules', []).extend(rules)


def message_rule_entries(msg):
    """requires / mutex / at_least: no C enforcement, shown as not checked."""

    from google.protobuf import descriptor_pb2
    from datagen import _load_validate_pb2

    validate_pb2 = _load_validate_pb2()
    options = descriptor_pb2.MessageOptions.FromString(msg.options.SerializeToString())
    if not options.HasExtension(validate_pb2.message):
        return []
    rules = options.Extensions[validate_pb2.message]
    entries = [{'id': 'message.requires', 'kind': 'UNSUPPORTED', 'fields': [f]} for f in rules.requires]
    entries += [{'id': 'message.mutex', 'kind': 'UNSUPPORTED', 'fields': list(g.fields)} for g in rules.mutex]
    entries += [{'id': 'message.at_least', 'kind': 'UNSUPPORTED', 'fields': list(a.fields)}
                for a in rules.at_least]
    return entries


def field_presence(field, syntax):
    """How the C struct tracks presence: repeated, oneof, explicit (has_ flag), required, implicit."""

    if field.label == 3:
        return 'repeated'
    if field.HasField('oneof_index') and not field.proto3_optional:
        return 'oneof'
    if field.proto3_optional or field.type in (10, 11):
        return 'explicit'
    if syntax != 'proto3':
        return 'required' if field.label == 2 else 'explicit'
    return 'implicit'


def field_storage(info):
    """nanopb storage of a field: static, pointer, callback or ignore (from its .options)."""

    if info is None:
        return {'storage': 'static'}
    storage = info.storage
    if storage == 'static':
        # Without a size nanopb falls back to a callback, which pb_validate skips.
        if info.label == 3 and not info.max_count:
            storage = 'callback'
        elif info.type in (9, 12) and not info.max_size:
            storage = 'callback'
    result = {'storage': storage}
    if storage == 'static':
        if info.type in (9, 12) and info.max_size:
            result['max_size'] = info.max_size
            if info.type == 12 and info.fixed_length:
                result['fixed_length'] = True
        if info.label == 3 and info.max_count:
            result['max_count'] = info.max_count
    return result


def nanopb_field_info(units):
    """{(message, field number): ProtoFieldInfo} from the units' .options files."""

    from datagen import DataGenerator

    infos = {}
    for unit in units:
        try:
            gen = unit_data_generator(unit, DataGenerator)
        except Exception:  # sizes stay unknown; the rules still work
            continue
        for full_name, msg in gen.registry.messages_by_full_name.items():
            for info in msg.fields.values():
                infos.setdefault((full_name.lstrip('.'), info.number), info)
    return infos


def build_schema(fds_list, field_infos=None):
    messages = {}
    enums = {}
    field_infos = field_infos or {}

    def add_enum(prefix, enum):
        enums[prefix + enum.name] = dict((v.number, v.name) for v in enum.value)

    def add_message(prefix, msg, syntax):
        full = prefix + msg.name
        fields = {}
        for fld in msg.field:
            entry = {
                'name': fld.name,
                'type': fld.type,
                'label': fld.label,
                'type_name': fld.type_name.lstrip('.'),
                'presence': field_presence(fld, syntax),
            }
            if entry['presence'] == 'oneof':
                entry['oneof'] = msg.oneof_decl[fld.oneof_index].name
            entry.update(field_storage(field_infos.get((full, fld.number))))
            rules = field_rule_entries(fld)
            if rules:
                entry['rules'] = rules
            fields[fld.number] = entry
        messages[full] = {'fields': fields, 'map_entry': msg.options.map_entry}
        message_rules = message_rule_entries(msg)
        if message_rules:
            messages[full]['message_rules'] = message_rules
        for nested in msg.nested_type:
            add_message(full + '.', nested, syntax)
        add_map_entry_rules(msg, messages)
        for enum in msg.enum_type:
            add_enum(full + '.', enum)

    seen = set()
    for fds in fds_list:
        for fdesc in fds.file:
            if fdesc.name in seen or is_option_proto(fdesc.name):
                continue
            seen.add(fdesc.name)
            prefix = fdesc.package + '.' if fdesc.package else ''
            for msg in fdesc.message_type:
                add_message(prefix, msg, fdesc.syntax or 'proto2')
            for enum in fdesc.enum_type:
                add_enum(prefix, enum)
    return messages, enums


LUA_KEYWORDS = frozenset('and break do else elseif end false for function goto if in local nil not or '
                         'repeat return then true until while'.split())


def lua_bytes(data):
    """Lua string literal for text or bytes (decimal escapes work in Lua 5.1 - 5.4)."""

    if isinstance(data, str):
        data = data.encode('utf-8')
    out = []
    for b in bytearray(data):
        if b in (0x22, 0x5c):
            out.append('\\' + chr(b))
        elif 32 <= b < 127:
            out.append(chr(b))
        else:
            out.append('\\%03d' % b)
    return '"' + ''.join(out) + '"'


def lua_value(value):
    if value is None:
        return 'nil'
    if isinstance(value, bool):
        return 'true' if value else 'false'
    if isinstance(value, int):
        return str(value) if abs(value) < 1 << 53 else repr(float(value))
    if isinstance(value, float):
        if value != value:
            return '(0/0)'
        if value in (float('inf'), float('-inf')):
            return 'math.huge' if value > 0 else '-math.huge'
        return repr(value)
    if isinstance(value, (str, bytes)):
        return lua_bytes(value)
    if isinstance(value, (list, tuple)):
        return '{ ' + ', '.join(lua_value(v) for v in value) + ' }'
    if isinstance(value, dict):
        items = []
        for key in value:
            if value[key] is None:
                continue
            if isinstance(key, str) and re.match(r'^[A-Za-z_]\w*$', key) and key not in LUA_KEYWORDS:
                items.append('%s = %s' % (key, lua_value(value[key])))
            else:
                items.append('[%s] = %s' % (lua_value(key), lua_value(value[key])))
        return '{ ' + ', '.join(items) + ' }'
    raise TypeError('cannot render %r as Lua' % (value,))


FIELD_KEYS = ('name', 'type', 'label', 'type_name', 'presence', 'oneof', 'storage', 'max_size',
              'max_count', 'fixed_length', 'rules')


def render_messages_lua(messages):
    out = []
    for name in sorted(messages):
        msg = messages[name]
        rules = msg.get('message_rules')
        out.append('    [%s] = { map_entry = %s,%s fields = {\n'
                   % (lua_str(name), 'true' if msg['map_entry'] else 'false',
                      ' message_rules = %s,' % lua_value(rules) if rules else ''))
        for number in sorted(msg['fields']):
            f = msg['fields'][number]
            parts = ['%s = %s' % (k, lua_value(f[k])) for k in FIELD_KEYS if f.get(k) is not None]
            out.append('      [%d] = { %s },\n' % (number, ', '.join(parts)))
        out.append('    } },\n')
    return out


def render_enums_lua(enums):
    out = []
    for name in sorted(enums):
        values = ', '.join('[%d] = %s' % (n, lua_str(v)) for n, v in sorted(enums[name].items()))
        out.append('    [%s] = { %s },\n' % (lua_str(name), values))
    return out


def render_schema_lua(messages, enums, protocols=None, scoped=None, roots=None):
    """The schema as Lua. ``scoped``: {protocol: (messages, enums)} that it defines differently."""

    out = ['-- Generated by nanopb_validate; do not edit.\n',
           'return {\n  messages = {\n']
    out += render_messages_lua(messages)
    out.append('  },\n  protocols = {\n')
    for name in sorted(protocols or {}):
        out.append('    [%s] = %s,\n' % (lua_str(name), lua_value(protocols[name])))
    out.append('  },\n  enums = {\n')
    out += render_enums_lua(enums)
    out.append('  },\n')
    if roots:
        out.append('  roots = %s,\n' % lua_value(roots))
    if scoped:
        out.append('  scoped = {\n')
        for name in sorted(scoped):
            own_messages, own_enums = scoped[name]
            out.append('  [%s] = {\n  messages = {\n' % lua_str(name))
            out += render_messages_lua(own_messages)
            out.append('  },\n  enums = {\n')
            out += render_enums_lua(own_enums)
            out.append('  },\n  },\n')
        out.append('  },\n')
    out.append('}\n')
    return ''.join(out)


def merge_unit_schemas(unit_schemas):
    """Merge [(unit name, messages, enums)] into one view plus each unit's differences.

    Folders are separate protocols, but a name like pkg.Msg can be defined
    differently in two of them. The first definition goes in the shared view
    and each unit that differs keeps its own, so Decode As uses the right one.
    Returns (messages, enums, {unit: (messages, enums)}, sorted conflicting names).
    """

    messages, enums, scoped, conflicts = {}, {}, {}, set()
    for unit, own_messages, own_enums in unit_schemas:
        for shared, own, slot in ((messages, own_messages, 0), (enums, own_enums, 1)):
            for name, definition in own.items():
                if shared.setdefault(name, definition) != definition:
                    scoped.setdefault(unit, ({}, {}))[slot][name] = definition
                    conflicts.add(name)
    return messages, enums, scoped, sorted(conflicts)


def schema_text(protos_root, extra_includes):
    """(Lua schema text, messages, names defined differently by several units) for every unit."""

    units = [Unit(protos_root, name, extra_includes) for name in find_units(protos_root)]
    if not units:
        raise BackendError(no_units_message(protos_root))
    # Always know google.protobuf.Any, even if no unit imports it.
    any_fds = compile_descriptor_set(['google/protobuf/any.proto'], [DEFAULT_INCLUDE])
    messages, enums, scoped, conflicts = merge_unit_schemas(
        [(u.name,) + build_schema([u.fds], nanopb_field_info([u])) for u in units])
    any_messages, any_enums = build_schema([any_fds])
    for name, definition in any_messages.items():
        messages.setdefault(name, definition)
    for name, definition in any_enums.items():
        enums.setdefault(name, definition)
    # Every folder with messages of its own is a protocol in Wireshark (its
    # packets are an Any; the C protocol filter needs the unit to use Any).
    protocols = dict((u.name, m) for u, m in ((u, protocol_messages(u)) for u in units) if m)
    roots = dict((u.name, unit_root(u)) for u in units if u.name in protocols and unit_root(u))
    return render_schema_lua(messages, enums, protocols, scoped, roots), messages, conflicts


def write_if_changed(path, text):
    """Write ``text`` unless the file already holds it; True if written."""

    if os.path.isfile(path):
        with open(path, encoding='utf-8') as handle:
            if handle.read() == text:
                return False
    directory = os.path.dirname(os.path.abspath(path))
    if not os.path.isdir(directory):
        os.makedirs(directory)
    with open(path, 'w', encoding='utf-8', newline='\n') as handle:
        handle.write(text)
    return True


def write_schema(protos_root, extra_includes, path):
    text, messages, _ = schema_text(protos_root, extra_includes)
    write_if_changed(path, text)
    return messages


def cmd_schema(args):
    messages = write_schema(args.protos_root, args.include, args.out)
    return {'schema': os.path.abspath(args.out), 'messages': sorted(messages)}


def prune_port_map(text, messages):
    """Split a saved port map into (entries still in ``messages``, stale entries).

    A saved map outlives the protos it was written for, so an entry for a
    message that is gone must not stop the protos now selected from loading.
    """

    kept, stale = [], []
    for proto, port, msg in parse_port_map(text, None):
        (kept if msg in messages else stale).append('%s:%d=%s' % (proto, port, msg))
    return ','.join(kept), stale


def protocols_of(schema):
    """Protocol names in a rendered schema."""

    block = schema.split('  protocols = {\n', 1)[-1].split('\n  },', 1)[0] if '  protocols = {' in schema else ''
    return re.findall(r'^    \["([^"]+)"\] = ', block, re.M)


def installed_protocol_ports(ports_path):
    """Protocol port entries of an installed ports.luadata."""

    try:
        with open(ports_path, encoding='utf-8') as handle:
            text = handle.read()
    except OSError:
        return []
    return [(t, int(port), name) for t, port, name in
            re.findall(r'\{ transport = "(udp|tcp)", port = (\d+), protocol = "([^"]+)" \}', text)]


def installed_port_map(ports_path):
    """The message entries of an installed ports.luadata as a port map string."""

    try:
        with open(ports_path, encoding='utf-8') as handle:
            text = handle.read()
    except OSError:
        return ''
    return ','.join('%s:%s=%s' % m for m in
                    re.findall(r'\{ transport = "(udp|tcp)", port = (\d+), message = "([^"]+)" \}', text))


def protos_fingerprint(protos_root, includes):
    """Cheap fingerprint of the protos: every .proto/.options path, size and
    mtime, plus this backend's own mtime (a tool update rebuilds the schema)."""

    import hashlib
    digest = hashlib.sha1()
    digest.update(str(int(os.stat(os.path.abspath(__file__)).st_mtime)).encode())
    for root in [protos_root] + list(includes or []):
        if not os.path.isdir(root):
            continue
        for dirpath, dirs, files in os.walk(root):
            dirs.sort()
            for name in sorted(files):
                if name.endswith(('.proto', '.options')):
                    path = os.path.join(dirpath, name)
                    st = os.stat(path)
                    digest.update(('%s|%d|%d\n' % (os.path.relpath(path, root), st.st_size,
                                                    int(st.st_mtime))).encode('utf-8'))
    return digest.hexdigest()


def install_schema(protos_root, includes, plugins, port_map, protocol_ports=None, drop_stale=False):
    """Install the dissector, its schema and port map into ``plugins``.

    ``protocol_ports`` of None keeps the protocol ports already installed.
    With ``drop_stale``, port map entries for messages not in these protos are
    removed instead of being an error (see prune_port_map).
    Only files whose content differs are written. Returns (result, changed, messages).
    """

    data_dir = os.path.join(plugins, 'nanopb')
    schema_path = os.path.join(data_dir, 'schema.luadata')
    fingerprint = protos_fingerprint(protos_root, includes)
    text, messages, conflicts = schema_text(protos_root, includes)
    changed = write_if_changed(schema_path, text)
    # refresh-schema compares against this to skip work when nothing changed.
    write_if_changed(os.path.join(data_dir, 'schema.fingerprint'), fingerprint + '\n')
    if protocol_ports is None:
        known = set(protocols_of(text))
        protocol_ports = [p for p in installed_protocol_ports(os.path.join(data_dir, 'ports.luadata'))
                          if p[2] in known]
    stale = []
    if drop_stale and port_map is not None:
        port_map, stale = prune_port_map(port_map, messages)
    ports = parse_port_map(port_map, messages)
    files = [schema_path]
    if port_map is not None or protocol_ports:
        lines = ['-- Default port map written by install-dissector.\nreturn {\n']
        for proto, port, msg in ports:
            lines.append('  { transport = %s, port = %d, message = %s },\n' % (lua_str(proto), port, lua_str(msg)))
        # Ports decoded with a protocol's own dissector (as with Decode As).
        for proto, port, name in protocol_ports:
            lines.append('  { transport = %s, port = %d, protocol = %s },\n' % (lua_str(proto), port, lua_str(name)))
        lines.append('}\n')
        ports_path = os.path.join(data_dir, 'ports.luadata')
        changed = write_if_changed(ports_path, ''.join(lines)) or changed
        files.append(ports_path)
    target = os.path.join(plugins, 'nanopb_any_dissector.lua')
    with open(tool_file('nanopb_any_dissector.lua'), encoding='utf-8') as handle:
        changed = write_if_changed(target, handle.read()) or changed
    files.insert(0, target)
    result = {'plugins_dir': plugins, 'files': files, 'messages': len(messages),
              'ports': ['%s:%d=%s' % p for p in ports] + ['%s:%d=<protocol %s>' % p for p in protocol_ports],
              'decode_as': [c_identifier(name).upper() for name in sorted(protocols_of(text))]}
    if conflicts:
        result['shared_names'] = conflicts
    if stale:
        result.update({'ports_pruned': True, 'port_map': port_map, 'stale_ports': stale})
    return result, changed, messages


def shared_names_note(names):
    return ('Defined differently by several protocols: %s. Each protocol uses its own definition; '
            'choose the protocol with Decode As, because plain NANOPB uses the first one.' % ', '.join(names))


def stale_ports_note(stale):
    return 'Removed from the port map, not in these protos: ' + ', '.join(stale)


def cmd_refresh_schema(args):
    """Rebuild the dissector schema if the protos changed since the last build.

    Run by nanopb_any_dissector.lua when Wireshark starts, with the protos
    directory saved in studio_config.luadata, so editing a .proto file needs
    no Load protos step. Exits quickly when nothing changed.
    """

    plugins = args.plugins_dir or default_plugins_dir()
    data_dir = os.path.join(plugins, 'nanopb')
    config = read_lua_config(os.path.join(data_dir, 'studio_config.luadata')) or {}
    protos_root = config.get('protos_root') or ''
    if not protos_root or not os.path.isdir(protos_root):
        return {'changed': False, 'skipped': 'no protos directory set',
                'summary': 'No protos directory set; nothing to refresh.'}
    includes = [i.strip() for i in (config.get('extra_includes') or '').split(';') if i.strip()]
    stored = ''
    try:
        with open(os.path.join(data_dir, 'schema.fingerprint')) as handle:
            stored = handle.read().strip()
    except (IOError, OSError):
        pass
    if stored == protos_fingerprint(protos_root, includes):
        return {'changed': False, 'summary': 'Schema is up to date with %s.' % protos_root}
    port_map = installed_port_map(os.path.join(data_dir, 'ports.luadata'))
    result, changed, _ = install_schema(protos_root, includes, plugins, port_map, drop_stale=True)
    result['changed'] = changed
    result['summary'] = 'Schema rebuilt from %s (%d messages).' % (protos_root, result['messages'])
    return result


def cmd_install_dissector(args):
    plugins = args.plugins_dir or default_plugins_dir()
    port_map = args.port_map
    saved = port_map is None
    if saved:
        port_map = installed_port_map(os.path.join(plugins, 'nanopb', 'ports.luadata'))
    result, changed, _ = install_schema(args.protos_root, args.include, plugins, port_map,
                                        drop_stale=saved or args.drop_stale_ports)
    result['changed'] = changed
    names = result['decode_as']
    lines = ['Loaded %d protocol(s) from %s:' % (len(names), args.protos_root)]
    lines += ['  %s' % n for n in names]
    lines += ['', 'Choose one:',
              '  for all NANOPB traffic: Edit > Preferences > Protocols > NANOPB > Protocol',
              '  per port: Analyze > Decode As > UDP port (or TCP port) > ' + (names[0] if names else '<FOLDER>'),
              '', '%d messages; ports: %s' % (result['messages'], ', '.join(result['ports']) or '(none)')]
    if result.get('stale_ports'):
        lines.append(stale_ports_note(result['stale_ports']))
    if result.get('shared_names'):
        lines.append(shared_names_note(result['shared_names']))
    result['summary'] = '\n'.join(lines)
    return result


def default_plugins_dir():
    """Personal Lua plugins folder (Help > About Wireshark > Folders)."""

    if os.name == 'nt':
        return os.path.join(os.environ.get('APPDATA', os.path.expanduser('~')), 'Wireshark', 'plugins')
    return os.path.join(os.path.expanduser('~'), '.local', 'lib', 'wireshark', 'plugins')


def tool_file(name):
    """A Lua plugin of this tool: <name>.lua in a checkout, <name>.lua.src in an installed copy."""

    for candidate in (name, name + '.src'):
        path = os.path.join(TOOL_DIR, candidate)
        if os.path.isfile(path):
            return path
    raise BackendError('%s not found in %s' % (name, TOOL_DIR))


def assert_no_lua(path):
    """Wireshark runs every .lua file below the plugins folder, so the copy may hold none."""

    for dirpath, _, filenames in os.walk(path):
        for name in filenames:
            if name.endswith('.lua'):
                raise BackendError('refusing to install %s: Wireshark would load it as a plugin'
                                   % os.path.join(dirpath, name))


def copy_project(src_root, dst):
    """Copy what the tool needs to ``dst`` with the checkout's layout: nanopb's
    runtime and generator, and validate/ (runtime, package, Lua as .src)."""

    if os.path.normcase(os.path.abspath(src_root)) == os.path.normcase(os.path.abspath(dst)):
        return  # running from the installed copy
    if os.path.isdir(dst):
        shutil.rmtree(dst)
    os.makedirs(dst)
    for name in RUNTIME_FILES + ('LICENSE.txt',):
        src = os.path.join(src_root, name)
        if os.path.isfile(src):
            shutil.copy(src, os.path.join(dst, name))
    ignore = shutil.ignore_patterns('__pycache__', '*.pyc', '*.lua')
    shutil.copytree(os.path.join(src_root, 'generator'), os.path.join(dst, 'generator'), ignore=ignore)
    src_validate = os.path.join(src_root, 'validate')
    dst_validate = os.path.join(dst, 'validate')
    shutil.copytree(os.path.join(src_validate, 'runtime'), os.path.join(dst_validate, 'runtime'))
    shutil.copytree(os.path.join(src_validate, 'nanopb_validate'), os.path.join(dst_validate, 'nanopb_validate'),
                    ignore=ignore)
    os.makedirs(os.path.join(dst_validate, 'wireshark'))
    for name in ('nanopb_any_dissector.lua', 'nanopb_studio.lua'):
        shutil.copy(os.path.join(src_validate, 'wireshark', name),
                    os.path.join(dst_validate, 'wireshark', name + '.src'))
    assert_no_lua(dst)


def git_commit(root):
    try:
        out = subprocess.run(['git', '-C', root, 'rev-parse', '--short', 'HEAD'], stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, universal_newlines=True)
        return out.stdout.strip() if out.returncode == 0 else None
    except OSError:
        return None


def check_environment():
    warnings = []
    try:
        import google.protobuf  # noqa: F401
    except ImportError:
        warnings.append('python package "protobuf" is missing for %s (pip install protobuf)' % sys.executable)
    try:
        import grpc_tools  # noqa: F401
    except ImportError:
        if not shutil.which('protoc'):
            warnings.append('neither grpcio-tools nor protoc found (pip install grpcio-tools)')
    return warnings


LUA_STRING_RE = re.compile(r'(\w+)\s*=\s*"((?:\\.|[^"\\])*)"')


def read_lua_config(path):
    """String keys of a studio_config.luadata file (written by us or by the studio's %q)."""

    if not os.path.isfile(path):
        return {}
    with open(path, encoding='utf-8') as handle:
        text = handle.read()
    unescape = {'n': '\n', '\n': '\n', 't': '\t'}
    return dict((key, re.sub(r'\\(.)', lambda m: unescape.get(m.group(1), m.group(1)), value, flags=re.S))
                for key, value in LUA_STRING_RE.findall(text))


def cmd_install_studio(args):
    plugins = args.plugins_dir or default_plugins_dir()
    data_dir = os.path.join(plugins, 'nanopb')
    project = os.path.join(data_dir, 'project')
    if not os.path.isdir(data_dir):
        os.makedirs(data_dir)
    copy_project(args.nanopb_root, project)
    files = []
    protos_root = os.path.abspath(args.protos_root) if args.protos_root else None
    for name in ('nanopb_studio.lua', 'nanopb_any_dissector.lua'):
        target = os.path.join(plugins, name)
        shutil.copy(tool_file(name), target)
        files.append(target)

    warnings = check_environment()
    info = {'source': os.path.abspath(args.nanopb_root), 'commit': git_commit(args.nanopb_root),
            'installed_at': time.strftime('%Y-%m-%d %H:%M:%S'), 'python': sys.executable, 'warnings': warnings}
    if os.path.isdir(project):
        with open(os.path.join(project, 'INSTALL_INFO.json'), 'w', newline='\n') as handle:
            json.dump(info, handle, indent=2)

    # Keep the user's last directories and port map; refresh where the tool lives.
    config_path = os.path.join(data_dir, 'studio_config.luadata')
    config = read_lua_config(config_path)
    config['python'] = sys.executable
    config['project'] = project
    config['nanopb_root'] = os.path.abspath(args.nanopb_root) if args.dev else ''
    loaded = None
    if protos_root:
        # One step: every menu starts from this directory, and Decode As already lists its protocols.
        loaded, _, _ = install_schema(protos_root, [], plugins, config.get('port_map', ''), drop_stale=True)
        config['protos_root'] = protos_root
        config['protos_root_fixed'] = '1'
        config['port_map'] = loaded.get('port_map', config.get('port_map', ''))
    keys = ['python', 'project', 'nanopb_root', 'protos_root', 'output_dir', 'extra_includes', 'port_map']
    keys += sorted(k for k in config if k not in keys)
    with open(config_path, 'w', newline='\n') as handle:
        handle.write('-- nanopb studio state (written by install-studio and the Tools > nanopb dialogs)\n'
                     'return {\n')
        for key in keys:
            handle.write('  %s = %s,\n' % (key, lua_str(config.get(key, ''))))
        handle.write('}\n')
    files += [project, config_path]
    result = {'plugins_dir': plugins, 'project': project, 'files': files, 'warnings': warnings,
              'mode': 'dev (uses %s)' % config['nanopb_root'] if args.dev else 'self-contained'}
    if loaded:
        result.update({'protos_root': protos_root, 'protocols': loaded['decode_as']})
    return result


def cmd_units(args):
    if args.names_only:
        units = find_units(args.protos_root)
        return {'protos_root': os.path.abspath(args.protos_root), 'units': units,
                'merged_into': merged_into(args.protos_root, units)}
    result = []
    for name in find_units(args.protos_root):
        unit = Unit(args.protos_root, name, args.include)
        result.append({'unit': name, 'protos': unit.protos, 'messages': unit.messages(),
                       'dependencies': [n for n in unit.generated_files() if n not in unit.names]})
    return {'protos_root': os.path.abspath(args.protos_root), 'units': result}


def cmd_pick_units(args):
    """Tick boxes in a scrolling list; Wireshark's own windows cannot show them."""

    if os.environ.get('NANOPB_WS_NO_TK'):
        raise BackendError('tick box window disabled')
    try:
        import tkinter
        from tkinter import ttk
    except ImportError:
        raise BackendError('tkinter is not available')
    off = set(n for n in args.off.split(',') if n)
    root = tkinter.Tk()
    root.title(args.title)
    root.geometry('420x480')
    root.attributes('-topmost', True)
    chosen = []

    buttons = ttk.Frame(root)
    buttons.pack(side='bottom', fill='x', padx=6, pady=6)
    canvas = tkinter.Canvas(root, highlightthickness=0)
    bar = ttk.Scrollbar(root, orient='vertical', command=canvas.yview)
    canvas.configure(yscrollcommand=bar.set)
    bar.pack(side='right', fill='y')
    canvas.pack(side='left', fill='both', expand=True)
    inner = ttk.Frame(canvas)
    canvas.create_window((0, 0), window=inner, anchor='nw')
    inner.bind('<Configure>', lambda _: canvas.configure(scrollregion=canvas.bbox('all')))
    canvas.bind_all('<MouseWheel>', lambda e: canvas.yview_scroll(-e.delta // 120, 'units'))

    boxes = [(n, tkinter.BooleanVar(value=n not in off)) for n in args.names.split(',')]
    for name, var in boxes:
        ttk.Checkbutton(inner, text=name, variable=var).pack(anchor='w', padx=8, pady=2)

    def set_all(value):
        for _, var in boxes:
            var.set(value)

    def generate():
        chosen.extend(n for n, var in boxes if var.get())
        if chosen:
            root.destroy()

    for label, command, side in (('Select all', lambda: set_all(True), 'left'),
                                 ('Select none', lambda: set_all(False), 'left'),
                                 ('Cancel', root.destroy, 'right'),
                                 ('Generate', generate, 'right')):
        ttk.Button(buttons, text=label, command=command).pack(side=side, padx=2)
    root.mainloop()
    return {'units': chosen}
