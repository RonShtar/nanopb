#!/usr/bin/env python3
'''Semantic tests for validate/nanopb_validate/datagen.py.

run_vectors.c proves that generated data survives pb_decode() and the C
validator.  This script covers what C cannot see:

  * an independent oracle re-checks every validate.proto rule of the generated
    data, also for rules the C validator does not implement yet (bytes
    prefix/suffix/contains/in/not_in, validate.message rules, timestamps);
  * generated dictionaries agree with the encoded message (oneofs, maps);
  * (nanopb) options are read from inline options and from .options files with
    nanopb's precedence;
  * impossible rules are reported instead of producing wrong data;
  * generation is reproducible and great.
'''

import os
import sys
import time
import tempfile
import math
import struct
from unittest import mock


def find_repo_root():
    start = os.path.abspath(os.path.dirname(__file__))
    while True:
        if os.path.isfile(os.path.join(start, 'validate', 'nanopb_validate', 'datagen.py')):
            return start
        parent = os.path.dirname(start)
        if parent == start:
            raise RuntimeError("could not find nanopb repository root")
        start = parent


REPO_ROOT = find_repo_root()
sys.path.insert(0, os.path.join(REPO_ROOT, 'validate', 'nanopb_validate'))

from google.protobuf import descriptor as pb_descriptor
from datagen import (
    DataGenerator, OutputFormat, ValidationRuleNotViolatableError)
import validate_pb2  # validate_proto/, on sys.path via datagen

HERE = os.path.dirname(os.path.abspath(__file__))
SEEDS = range(60)
CPP = pb_descriptor.FieldDescriptor


def load(name):
    return DataGenerator(os.path.join(HERE, name), [HERE])


# ---------------------------------------------------------------------------
# Independent rule oracle
# ---------------------------------------------------------------------------

INT_TYPES = ('int32', 'int64', 'uint32', 'uint64', 'sint32', 'sint64',
             'fixed32', 'fixed64', 'sfixed32', 'sfixed64', 'float', 'double')


def is_repeated(fd):
    try:
        return fd.is_repeated
    except AttributeError:
        return fd.label == CPP.LABEL_REPEATED


def has_presence(fd):
    try:
        return fd.has_presence
    except AttributeError:
        return fd.containing_oneof is not None or fd.type == CPP.TYPE_MESSAGE


def has(rules, name):
    '''HasField() that tolerates rule messages without that field (EnumRules).'''
    return name in rules.DESCRIPTOR.fields_by_name and rules.HasField(name)


def numeric_problems(rules, value, prefix):
    out = []
    if has(rules, 'const_value') and value != rules.const_value:
        out.append(prefix + 'const')
    if has(rules, 'gt') and not value > rules.gt:
        out.append(prefix + 'gt')
    if has(rules, 'gte') and not value >= rules.gte:
        out.append(prefix + 'gte')
    if has(rules, 'lt') and not value < rules.lt:
        out.append(prefix + 'lt')
    if has(rules, 'lte') and not value <= rules.lte:
        out.append(prefix + 'lte')
    if len(getattr(rules, 'in')) and value not in list(getattr(rules, 'in')):
        out.append(prefix + 'in')
    if len(rules.not_in) and value in list(rules.not_in):
        out.append(prefix + 'not_in')
    return out


def blob_problems(rules, value, prefix, is_text):
    out = []
    size = len(value.encode('utf-8')) if is_text else len(value)
    if rules.HasField('const_value') and value != rules.const_value:
        out.append(prefix + 'const')
    if rules.HasField('min_len') and size < rules.min_len:
        out.append(prefix + 'min_len')
    if rules.HasField('max_len') and size > rules.max_len:
        out.append(prefix + 'max_len')
    if rules.HasField('prefix') and not value.startswith(rules.prefix):
        out.append(prefix + 'prefix')
    if rules.HasField('suffix') and not value.endswith(rules.suffix):
        out.append(prefix + 'suffix')
    if rules.HasField('contains') and rules.contains not in value:
        out.append(prefix + 'contains')
    if len(getattr(rules, 'in')) and value not in list(getattr(rules, 'in')):
        out.append(prefix + 'in')
    if len(rules.not_in) and value in list(rules.not_in):
        out.append(prefix + 'not_in')
    if is_text:
        import ipaddress
        import re
        host = re.compile(r'^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$')
        if rules.ascii and not value.isascii():
            out.append(prefix + 'ascii')
        if rules.hostname and not host.match(value):
            out.append(prefix + 'hostname')
        if rules.email:
            local, _, domain = value.partition('@')
            if (not local or not host.match(domain) or '@' in domain or local.startswith('.')
                    or local.endswith('.') or '..' in local or ' ' in value):
                out.append(prefix + 'email')
        for flag, cls in (('ipv4', ipaddress.IPv4Address), ('ipv6', ipaddress.IPv6Address)):
            if getattr(rules, flag):
                try:
                    cls(value)
                except ValueError:
                    out.append(prefix + flag)
        if rules.ip:
            try:
                ipaddress.ip_address(value)
            except ValueError:
                out.append(prefix + 'ip')
    return out


def scalar_problems(fd, rules, value, prefix=''):
    '''Rules of one value (or one repeated entry) of field ``fd``.'''
    kind = {CPP.TYPE_INT32: 'int32', CPP.TYPE_INT64: 'int64', CPP.TYPE_UINT32: 'uint32',
            CPP.TYPE_UINT64: 'uint64', CPP.TYPE_SINT32: 'sint32', CPP.TYPE_SINT64: 'sint64',
            CPP.TYPE_FIXED32: 'fixed32', CPP.TYPE_FIXED64: 'fixed64',
            CPP.TYPE_SFIXED32: 'sfixed32', CPP.TYPE_SFIXED64: 'sfixed64',
            CPP.TYPE_FLOAT: 'float', CPP.TYPE_DOUBLE: 'double'}.get(fd.type)
    out = []
    if kind and rules.HasField(kind):
        out += numeric_problems(getattr(rules, kind), value, prefix)
    elif fd.type == CPP.TYPE_BOOL and rules.HasField('bool'):
        if rules.bool.HasField('const_value') and value != rules.bool.const_value:
            out.append(prefix + 'const')
    elif fd.type == CPP.TYPE_STRING and rules.HasField('string'):
        out += blob_problems(rules.string, value, prefix, True)
    elif fd.type == CPP.TYPE_BYTES and rules.HasField('bytes'):
        out += blob_problems(rules.bytes, value, prefix, False)
    elif fd.type == CPP.TYPE_ENUM and rules.HasField('enum'):
        out += numeric_problems(rules.enum, value, prefix)
        if rules.enum.defined_only and value not in fd.enum_type.values_by_number:
            out.append(prefix + 'defined_only')
    return out


def message_problems(message, path=''):
    '''Return every violated rule of ``message`` (recursively) as strings.'''
    problems = []
    descriptor = message.DESCRIPTOR
    now = time.time()
    for fd in descriptor.fields:
        options = fd.GetOptions()
        rules = options.Extensions[validate_pb2.rules] if options.HasExtension(validate_pb2.rules) else None
        name = path + fd.name
        oneof = fd.containing_oneof
        if oneof is not None and not getattr(fd, 'proto3_optional', False):
            if message.WhichOneof(oneof.name) != fd.name:
                continue        # unselected oneof arms are not part of the message
        value = getattr(message, fd.name)
        is_map = (fd.type == CPP.TYPE_MESSAGE and fd.message_type.GetOptions().map_entry)
        repeated = is_repeated(fd)

        if rules is not None and rules.required:
            if fd.type == CPP.TYPE_MESSAGE and not repeated and not message.HasField(fd.name):
                problems.append(name + ':required')
            elif has_presence(fd) and not repeated and not message.HasField(fd.name):
                problems.append(name + ':required')

        if is_map:
            if rules is not None and rules.HasField('map'):
                if rules.map.HasField('min_pairs') and len(value) < rules.map.min_pairs:
                    problems.append(name + ':min_pairs')
                if rules.map.HasField('max_pairs') and len(value) > rules.map.max_pairs:
                    problems.append(name + ':max_pairs')
            continue

        if repeated:
            items = list(value)
            if rules is not None and rules.HasField('repeated'):
                rep = rules.repeated
                if rep.HasField('min_items') and len(items) < rep.min_items:
                    problems.append(name + ':min_items')
                if rep.HasField('max_items') and len(items) > rep.max_items:
                    problems.append(name + ':max_items')
                if rep.unique and fd.type != CPP.TYPE_MESSAGE and len(set(items)) != len(items):
                    problems.append(name + ':unique')
                if rep.HasField('items'):
                    for index, item in enumerate(items):
                        problems += ['%s[%d]:%s' % (name, index, p)
                                     for p in scalar_problems(fd, rep.items, item)]
            if fd.type == CPP.TYPE_MESSAGE:
                for index, item in enumerate(items):
                    if fd.message_type.full_name != 'google.protobuf.Any':
                        problems += message_problems(item, '%s[%d].' % (name, index))
            continue

        if fd.type == CPP.TYPE_MESSAGE:
            present = message.HasField(fd.name)
            if fd.message_type.full_name == 'google.protobuf.Any':
                if present and rules is not None and rules.HasField('any'):
                    allowed = [u for u in getattr(rules.any, 'in')]
                    denied = [u for u in rules.any.not_in]
                    if allowed and value.type_url not in allowed:
                        problems.append(name + ':any.in')
                    if value.type_url in denied:
                        problems.append(name + ':any.not_in')
            elif fd.message_type.full_name == 'google.protobuf.Timestamp':
                if present and rules is not None and rules.HasField('timestamp'):
                    stamp = value.seconds + value.nanos / 1e9
                    if rules.timestamp.gt_now and not stamp > now:
                        problems.append(name + ':gt_now')
                    if rules.timestamp.lt_now and not stamp < now:
                        problems.append(name + ':lt_now')
                    if rules.timestamp.HasField('within') and abs(stamp - now) > rules.timestamp.within.seconds:
                        problems.append(name + ':within')
                if present and not (0 <= value.nanos <= 999999999 and 0 <= value.seconds <= 253402300799):
                    problems.append(name + ':timestamp-range')
            elif present:
                problems += message_problems(value, name + '.')
            continue

        # Fields without presence cannot be told apart from "unset", which is
        # how nanopb treats them as well, so the rules apply regardless.
        if rules is not None:
            problems += ['%s:%s' % (name, p) for p in scalar_problems(fd, rules, value)]

    # validate.message rules
    options = descriptor.GetOptions()
    if options.HasExtension(validate_pb2.message):
        mrules = options.Extensions[validate_pb2.message]

        def is_set(field_name):
            fd = descriptor.fields_by_name[field_name]
            return message.HasField(field_name) if has_presence(fd) else bool(getattr(message, field_name))

        for required in mrules.requires:
            if not is_set(required):
                problems.append(path + 'requires:' + required)
        for group in mrules.mutex:
            if sum(1 for f in group.fields if is_set(f)) > 1:
                problems.append(path + 'mutex')
        for rule in mrules.at_least:
            if sum(1 for f in rule.fields if is_set(f)) < rule.n:
                problems.append(path + 'at_least')
    return problems


def parse(generator, name, data):
    cls = generator.registry.get_message_class(name)
    message = cls()
    message.ParseFromString(generator.encode_to_binary(name, data))
    return message


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def expect_raises(error_type, fn, *args, **kwargs):
    try:
        fn(*args, **kwargs)
    except error_type as exc:
        return exc
    raise AssertionError("%s did not raise %s" % (fn.__name__, error_type.__name__))


def test_every_rule_holds_for_generated_data():
    '''Valid data satisfies every rule, for all messages and many seeds.'''
    total = 0
    for proto in ('stress.proto', 'decode_only.proto', 'python_only.proto', 'legacy.proto'):
        generator = load(proto)
        for name in generator.get_messages():
            if name.startswith('Unsat'):
                continue
            for seed in SEEDS:
                data = generator.generate_valid(name, seed=seed)
                message = parse(generator, name, data)
                problems = message_problems(message)
                assert not problems, "%s %s seed=%d violates %s\n%s" % (proto, name, seed, problems, data)
                total += 1
    assert total > 1000, total


def test_invalid_data_violates_the_requested_rule():
    '''generate_invalid breaks the requested rule and (preferably) only that rule.'''
    generator = load('python_only.proto')
    checked = 0
    for name in ('BytesRules', 'Stamps', 'OneofRequired', 'MessageRules'):
        info = generator.registry.resolve_message(name)
        for field_name, finfo in info.fields.items():
            for rule in sorted({c.rule_type for c in finfo.constraints}):
                try:
                    data = generator.generate_invalid(name, violate_field=field_name,
                                                      violate_rule=rule, seed=11)
                except ValidationRuleNotViolatableError:
                    continue
                problems = message_problems(parse(generator, name, data))
                relevant = [p for p in problems if p.startswith(field_name + ':')]
                if rule in ('oneof_required',):
                    continue   # absence of a oneof arm: no per-field oracle
                assert relevant, "%s.%s.%s produced valid data: %s" % (name, field_name, rule, data)
                checked += 1
    assert checked >= 15, checked


def test_bytes_rules():
    generator = load('python_only.proto')
    for seed in SEEDS:
        data = generator.generate_valid('BytesRules', seed=seed)
        assert data['pre_suf'].startswith(b'\x01\x02') and data['pre_suf'].endswith(b'\xff')
        assert b'\x10\x20' in data['pre_suf'] and len(data['pre_suf']) <= 16
        assert data['pick'] in (b'\x01\x02\x03', b'\x09')
        assert len(data['avoid']) == 1 and data['avoid'] != b'\x00'
        assert data['fixed'] == b'\xde\xad\xbe\xef'
        assert len(data['exact4']) == 4          # fixed_length
        assert data['oversized_in'] == b'ab'      # the other entry does not fit max_size 3


def test_dynamic_fields_are_not_clamped():
    '''Callback/pointer fields have no nanopb size limit: only the rules apply.'''
    generator = load('python_only.proto')
    for seed in SEEDS:
        data = generator.generate_valid('Dynamic', seed=seed)
        assert 30 <= len(data['long_text']) <= 40
        assert len(data['long_blob']) >= 50
        assert 8 <= len(data['many']) <= 9
        assert len(data['pointer']) >= 5       # FT_POINTER ignores max_size


def test_message_rules():
    generator = load('python_only.proto')
    for seed in SEEDS:
        data = generator.generate_valid('MessageRules', seed=seed)
        assert 'b' in data                                           # requires
        assert not ('c' in data and 'd' in data)                     # mutex
        assert sum(1 for f in ('a', 'b', 'c') if f in data) >= 2     # at_least


def test_timestamps_and_durations():
    generator = load('python_only.proto')
    for seed in SEEDS:
        message = parse(generator, 'Stamps', generator.generate_valid('Stamps', seed=seed))
        assert message.future.seconds > time.time() + 86400
        assert message.past.seconds < time.time() - 3600
        assert abs(message.recent.seconds - time.time()) <= 3600
        assert 0 <= message.plain.nanos <= 999999999
        same_sign = (message.span.seconds < 0 and message.span.nanos <= 0) or \
                    (message.span.seconds >= 0 and message.span.nanos >= 0)
        assert same_sign, message.span


def test_oneof_dict_matches_encoded_message():
    '''Only one oneof member is generated, so the dict is what gets encoded.'''
    for proto, name in (('stress.proto', 'Choice'), ('python_only.proto', 'OneofRequired')):
        generator = load(proto)
        info = generator.registry.resolve_message(name)
        members = [f.name for f in info.fields.values() if f.oneof_index is not None]
        seen = set()
        for seed in SEEDS:
            data = generator.generate_valid(name, seed=seed)
            present = [m for m in members if m in data]
            assert len(present) == 1, (name, data)
            seen.add(present[0])
            message = parse(generator, name, data)
            assert message.WhichOneof(info.descriptor_proto.oneof_decl[0].name) == present[0]
        if name == 'Choice':
            assert len(seen) >= 3, seen          # every arm gets exercised
        else:
            assert seen == {'text'}, seen        # oneof_required pins the arm


def test_maps_are_generated():
    generator = load('stress.proto')
    sizes = set()
    for seed in SEEDS:
        data = generator.generate_valid('Maps', seed=seed)
        message = parse(generator, 'Maps', data)
        assert 1 <= len(message.by_name) <= 3
        assert len(message.by_id) <= 2 and len(message.inners) <= 2
        assert all(len(k.encode()) <= 7 for k in message.by_name)
        assert all(len(v.encode()) <= 5 for v in message.by_id.values())
        sizes.add(len(message.by_name))
    assert len(sizes) > 1, sizes


def test_options_files_and_precedence():
    '''.options masks, file ordering and inline options (see decode_only.options).'''
    generator = load('decode_only.proto')
    fields = generator.get_all_fields('Wild')
    assert fields['a'].capacity() == 5              # Wild.* max_size:6 (string: minus NUL)
    assert fields['special'].capacity() == 9        # later, more specific line wins
    assert fields['inline_wins'].capacity() == 2    # inline (nanopb) beats .options
    assert fields['blob'].capacity() == 6
    assert fields['nums'].item_capacity() == 3
    assert fields['metas'].item_capacity() == 2
    # Options of an imported file come from the imported file's own .options.
    meta = generator.registry.resolve_message('stresscommon.Meta').fields
    assert meta['label'].capacity() == 5 and meta['ids'].item_capacity() == 2
    assert meta['token'].capacity() == 4
    for seed in SEEDS:
        data = generator.generate_valid('Wild', seed=seed)
        assert len(data['a']) <= 5 and len(data['b']) <= 5 and len(data['special']) <= 9
        assert len(data['inline_wins']) <= 2 and len(data['nums']) <= 3 and len(data['blob']) <= 6


def test_explicit_options_file():
    '''DataGenerator(options_files=...) applies additional .options files.'''
    with tempfile.TemporaryDirectory() as tmp:
        options = os.path.join(tmp, 'extra.options')
        with open(options, 'w') as handle:
            handle.write('# comment\n/* block */\n'
                         'stress.Strings.cap_only max_size:4 // inline option of cap_only wins\n'
                         'stress.Strings.opt_file_cap max_length:2\n')
        generator = DataGenerator(os.path.join(HERE, 'stress.proto'), [HERE], options_files=[options])
        # nanopb gives options written in the .proto the last word ...
        assert generator.get_field_info('Strings', 'cap_only').capacity() == 15
        # ... but an explicit file overrides the .options file next to the proto.
        assert generator.get_field_info('Strings', 'opt_file_cap').capacity() == 2
        for seed in SEEDS:
            assert len(generator.generate_valid('Strings', seed=seed)['opt_file_cap']) <= 2


def test_unsatisfiable_rules_are_reported():
    generator = load('python_only.proto')
    for name in ('UnsatMinLen', 'UnsatConstSize', 'UnsatIntSize', 'UnsatIntRange', 'UnsatCount',
                 'UnsatUnique', 'UnsatAffix', 'UnsatFloat', 'UnsatNotIn'):
        expect_raises(ValueError, generator.generate_valid, name, seed=1)


def test_invalid_generation_errors():
    generator = load('stress.proto')
    expect_raises(ValueError, generator.generate_invalid, 'Ints', violate_field='nope')
    expect_raises(ValueError, generator.generate_invalid, 'Ints', violate_field='free_i32')
    expect_raises(ValueError, generator.generate_invalid, 'Ints', violate_field='a', violate_rule='min_len')
    # uint32 lte = 4294967295 is the type maximum
    expect_raises(ValidationRuleNotViolatableError, generator.generate_invalid, 'Ints',
                  violate_field='d', violate_rule='lte')
    # max_len 8 can be exceeded (buffer holds 9), tight_cap's min_len 1 can not be below 0 chars... but can be empty
    data = generator.generate_invalid('Strings', violate_field='len_ruled', violate_rule='max_len')
    assert len(data['len_ruled']) == 9      # one past max_len, still fits max_size 10
    data = generator.generate_invalid('Strings', violate_field='len_ruled', violate_rule='min_len')
    assert len(data['len_ruled']) == 1
    # several fields at once
    data = generator.generate_invalid('Ints', violate_field=['a', 'b'])
    assert not -100 < data['a'] < 100 or data['b'] != 5


def test_invalid_data_is_always_decodable():
    '''Violations stay inside what nanopb can store (int_size, max_size, max_count).'''
    generator = load('stress.proto')
    checks = 0
    for name in ('SmallInts', 'Strings', 'Blobs', 'Repeats', 'Enums'):
        info = generator.registry.resolve_message(name)
        for field_name, finfo in info.fields.items():
            for rule in sorted({c.rule_type for c in finfo.constraints}):
                try:
                    data = generator.generate_invalid(name, violate_field=field_name, violate_rule=rule, seed=5)
                except ValidationRuleNotViolatableError:
                    continue
                value = data[field_name] if field_name in data else None
                capacity = finfo.capacity()
                if capacity is not None and isinstance(value, (str, bytes)):
                    assert len(value.encode() if isinstance(value, str) else value) <= capacity
                if finfo.item_capacity() is not None and isinstance(value, list):
                    assert len(value) <= finfo.item_capacity()
                if finfo.get_type_name() in ('int32', 'uint32', 'sint32', 'int64', 'uint64') and not finfo.is_repeated():
                    low, high = finfo.integer_bounds()
                    assert low <= value <= high, (name, field_name, rule, value)
                checks += 1
    assert checks > 40, checks


def test_reproducible_and_varied():
    generator = load('stress.proto')
    for name in ('Strings', 'Repeats', 'Envelope', 'AnyHolder'):
        first = generator.generate_valid(name, seed=77)
        assert first == generator.generate_valid(name, seed=77)
        assert any(generator.generate_valid(name, seed=s) != first for s in range(5, 15))
    # the encoded bytes are identical too
    assert (generator.encode_to_binary('Envelope', generator.generate_valid('Envelope', seed=3)) ==
            generator.encode_to_binary('Envelope', generator.generate_valid('Envelope', seed=3)))


def test_any_payloads_respect_any_storage():
    '''google/protobuf/any.options limits type_url to 79 and value to 96 bytes.'''
    generator = load('stress.proto')
    url_limit, value_limit = generator._any_limits()
    assert (url_limit, value_limit) == (79, 96), (url_limit, value_limit)
    kinds = set()
    for seed in range(200):
        data = generator.generate_valid('AnyHolder', seed=seed)
        for any_value in [data['one'], data['single'], data['open'], data['denied']] + data['many']:
            assert len(any_value['type_url']) <= url_limit
            assert len(any_value['value']) <= value_limit, any_value
            kinds.add(any_value['type_url'])
        assert data['one']['type_url'] in ('type.googleapis.com/stress.PayloadA',
                                           'type.googleapis.com/stress.PayloadB')
        assert data['denied']['type_url'] not in ('type.googleapis.com/stress.PayloadA',
                                                  'type.googleapis.com/stress.PayloadB')
    assert 'type.googleapis.com/stress.PayloadHuge' not in kinds     # never fits
    assert len(kinds) >= 5, kinds


def test_float_step():
    for single, float_format, int_format, one_bits, max_bits in (
            (True, '<f', '<I', 0x3f800000, 0x7f7fffff),
            (False, '<d', '<Q', 0x3ff0000000000000, 0x7fefffffffffffff)):
        def from_bits(bits):
            return struct.unpack(float_format, struct.pack(int_format, bits))[0]

        step = lambda value, up: DataGenerator._float_step(value, up, single)
        tiny = from_bits(1)
        maximum = from_bits(max_bits)
        for zero in (0.0, -0.0):
            assert step(zero, True) == tiny
            assert step(zero, False) == -tiny
        assert step(tiny, False) == 0.0
        assert step(-tiny, True) == 0.0
        assert math.copysign(1.0, step(-tiny, True)) == -1.0
        assert step(1.0, True) == from_bits(one_bits + 1)
        assert step(1.0, False) == from_bits(one_bits - 1)
        assert step(-1.0, True) == -from_bits(one_bits - 1)
        assert step(-1.0, False) == -from_bits(one_bits + 1)
        assert step(maximum, True) == math.inf
        assert step(-maximum, False) == -math.inf
        assert step(math.inf, False) == maximum
        assert step(-math.inf, True) == -maximum
        assert step(math.inf, True) == math.inf
        assert step(-math.inf, False) == -math.inf
        assert math.isnan(step(math.nan, True))
        assert math.isnan(step(math.nan, False))


def test_output_formats():
    generator = load('stress.proto')
    data = generator.generate_valid('Inner', seed=1)
    binary = generator.encode_to_binary('Inner', data)
    assert generator.format_output(binary, OutputFormat.HEX_STRING) == binary.hex()
    c_array = generator.format_output(binary, OutputFormat.C_ARRAY, 'inner')
    assert 'const uint8_t inner[]' in c_array and ('inner_size = %d' % len(binary)) in c_array


def test_float_step_without_nextafter():
    with mock.patch.object(math, 'nextafter', None, create=True):
        test_float_step()


def main():
    tests = [(name, fn) for name, fn in sorted(globals().items())
             if name.startswith('test_') and callable(fn)]
    for name, fn in tests:
        fn()
        print('ok', name)
    print('OK')


if __name__ == '__main__':
    main()
