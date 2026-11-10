#!/usr/bin/env python3
'''Generate the test vectors for the data_generator_stress test case.

For every message in stress.proto this uses validate/nanopb_validate/datagen.py
to produce
  * VALID vectors for many seeds: they have to decode with pb_decode() (so they
    respect the (nanopb) max_size / max_count / int_size limits) and pass the
    generated validator, including every message carried inside a
    google.protobuf.Any field;
  * INVALID vectors, one per field and validate rule: they still have to
    decode, but the validator has to reject exactly that field.

The vectors are written to a C header that is consumed by run_vectors.c.
'''

import os
import sys


def find_repo_root():
    '''Locate the nanopb root, also when running from the scons build dir.'''
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

from datagen import DataGenerator, ValidationRuleNotViolatableError

PROTO_DIR = os.path.dirname(os.path.abspath(__file__))
PROTO_FILE = os.path.join(PROTO_DIR, 'stress.proto')

# STRESS_SEEDS=n gives a longer soak run than the default CI setting.
VALID_SEEDS = int(os.environ.get('STRESS_SEEDS', '40'))
INVALID_SEEDS = max(3, VALID_SEEDS // 10)

# Rules that cannot be violated by data that nanopb is able to decode.  Each
# entry documents why; an unexpected entry (or a missing one) fails the build
# so that the generator can neither silently drop nor invent violations.
EXPECTED_UNVIOLATABLE = {
    # uint32 lte = 4294967295 is the type maximum: no uint32 is larger.
    'stress.Ints.d.lte',
}

# Constraint ids the C validator reports.
def expected_constraint(finfo, rule):
    type_name = finfo.get_type_name()
    if rule == 'required':
        return 'required'
    if rule.startswith('items.'):
        return None          # reported under the per-entry rule id; any id accepted
    if finfo.is_map():
        return {'min_items': 'map.min_pairs', 'max_items': 'map.max_pairs'}.get(rule)
    if finfo.is_repeated() and rule in ('min_items', 'max_items', 'unique'):
        return 'repeated.' + rule
    if finfo.is_any():
        return 'any.' + rule
    if type_name in ('string', 'bytes'):
        return '%s.%s' % (type_name, rule)
    if type_name == 'enum':
        return 'enum.' + rule
    if type_name == 'bool':
        return 'bool.const'
    return '%s.%s' % (type_name, rule)


def c_bytes(name, data):
    values = ', '.join('0x%02x' % byte for byte in data) or '0'
    return 'static const uint8_t %s[] = {%s};\n' % (name, values)


def c_string(text):
    if text is None:
        return 'NULL'
    return '"%s"' % text.replace('\\', '\\\\').replace('"', '\\"')


def collect(proto_name, validated, vectors, skipped):
    '''Append the vectors of every message in one .proto file.'''

    proto_file = os.path.join(PROTO_DIR, proto_name)
    generator = DataGenerator(proto_file, [PROTO_DIR])
    package = generator.file_descriptor.package
    messages = generator.get_messages()

    for message in messages:
        full_name = '%s.%s' % (package, message)
        for seed in range(VALID_SEEDS):
            data = generator.generate_valid(message, seed=seed)
            vectors.append(('valid %s seed=%d' % (full_name, seed), full_name,
                            generator.encode_to_binary(message, data),
                            1 if validated else 2, None, None))

        info = generator.registry.resolve_message(message)
        for field_name, finfo in info.fields.items():
            rules = sorted({c.rule_type for c in finfo.constraints} |
                           {'items.' + c.rule_type for c in finfo.item_constraints})
            for rule in rules:
                for seed in range(INVALID_SEEDS):
                    key = '%s.%s.%s' % (full_name, field_name, rule)
                    try:
                        data = generator.generate_invalid(
                            message, violate_field=field_name, violate_rule=rule,
                            seed=1000 + seed)
                    except ValidationRuleNotViolatableError as exc:
                        skipped.add(key)
                        sys.stderr.write('skipped %s: %s\n' % (key, exc))
                        break
                    vectors.append(('invalid %s' % key, full_name,
                                    generator.encode_to_binary(message, data),
                                    0 if validated else 2,
                                    expected_constraint(finfo, rule), field_name))

    if validated:
        collect_nested(generator, package, vectors)
    return [(package, message) for message in messages]


def collect_nested(generator, package, vectors):
    '''Violations inside sub-messages kept in repeated fields, maps and oneof arms.'''

    cases = [
        ('Repeats', 'inners', lambda bad: [bad]),
        ('Maps', 'inners', lambda bad: {7: bad}),
        ('Choice', 'inner', lambda bad: bad),
    ]
    for message, field_name, wrap in cases:
        for seed in range(INVALID_SEEDS):
            data = generator.generate_valid(message, seed=seed)
            for inner_field in ('name', 'v'):
                bad = generator.generate_invalid('Inner', violate_field=inner_field, seed=seed)
                data[field_name] = wrap(bad)
                if message == 'Choice':
                    for sibling in ('num', 'text', 'blob'):
                        data.pop(sibling, None)
                vectors.append(('invalid nested %s.%s.%s seed=%d' % (message, field_name, inner_field, seed),
                                '%s.%s' % (package, message),
                                generator.encode_to_binary(message, data), 0, None, None))


def main():
    if len(sys.argv) != 2:
        sys.stderr.write("usage: generate_vectors.py <output header>\n")
        return 1

    vectors = []   # (name, full message name, bytes, kind, constraint, field)
    skipped = set()
    validated_messages = collect('stress.proto', True, vectors, skipped)
    decode_messages = collect('decode_only.proto', False, vectors, skipped)
    decode_messages += collect('legacy.proto', False, vectors, skipped)

    unexpected = skipped - set(EXPECTED_UNVIOLATABLE)
    missing = set(EXPECTED_UNVIOLATABLE) - skipped
    if unexpected or missing:
        sys.stderr.write('unexpected unviolatable rules: %s\n' % sorted(unexpected))
        sys.stderr.write('rules that became violatable: %s\n' % sorted(missing))
        return 1

    lines = [
        '/* Automatically generated by generate_vectors.py, do not edit. */\n',
        '#ifndef STRESS_VECTORS_H\n#define STRESS_VECTORS_H\n\n',
        '#include <stddef.h>\n#include <stdint.h>\n\n',
        '/* Messages with generated validators / messages that are only decoded. */\n',
        '#define STRESS_TYPES(X) \\\n',
    ]
    lines.extend('    X(%s, %s) \\\n' % (pkg.replace('.', '_'), name) for pkg, name in validated_messages)
    lines.append('\n#define DECODE_TYPES(X) \\\n')
    lines.extend('    X(%s, %s) \\\n' % (pkg.replace('.', '_'), name) for pkg, name in decode_messages)
    lines.append('\n')

    for index, vector in enumerate(vectors):
        lines.append(c_bytes('vec_data_%d' % index, vector[2]))

    lines.append('\n/* kind: 1 = valid, 0 = invalid, 2 = only has to decode */\n')
    lines.append('static const struct\n{\n    const char *name;\n    const char *message;\n'
                 '    const uint8_t *data;\n    size_t size;\n    int kind;\n'
                 '    const char *constraint;\n    const char *field;\n} vectors[] = {\n')
    for index, (name, message, data, kind, constraint, field) in enumerate(vectors):
        lines.append('    {%s, %s, vec_data_%d, %d, %d, %s, %s},\n' % (
            c_string(name), c_string(message), index, len(data), kind,
            c_string(constraint), c_string(field)))
    lines.append('};\n\n#endif\n')

    with open(sys.argv[1], 'w') as handle:
        handle.write(''.join(lines))
    sys.stderr.write('%d vectors (%d invalid rules skipped)\n' % (len(vectors), len(skipped)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
