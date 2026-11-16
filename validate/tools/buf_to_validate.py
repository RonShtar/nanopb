#!/usr/bin/env python3
"""Convert protovalidate (buf.validate) annotations to nanopb-validate's (validate.rules).

A standalone script: one file, Python 3 standard library only, no import from
nanopb_validate. Copy it anywhere.

    python buf_to_validate.py PROTOS --out CONVERTED
    python buf_to_validate.py one.proto --out CONVERTED

PROTOS is a .proto file or a folder of them. Every .proto file is rewritten into
CONVERTED with the same relative path (the original is never modified); every
other file (for example *.options) is copied unchanged. A folder named
buf/validate (the vendored validate.proto of protovalidate) is not copied.

What is converted, field by field, keeping comments and layout:

    import "buf/validate/validate.proto";   ->  import "validate.proto";
    (buf.validate.field).string.min_len = 1 ->  (validate.rules).string.min_len = 1
    (buf.validate.field).uint32 = {gte: 1, lte: 9}
                                            ->  (validate.rules).uint32.gte = 1, (validate.rules).uint32.lte = 9
    const -> const_value;   len -> min_len + max_len (strings and bytes)

Rules nanopb-validate cannot enforce are dropped and reported, never converted
into something that only looks equivalent: cel, ignore, pattern, *_bytes,
uri/uuid/... formats, absolute timestamp bounds, duration rules, message-level
cel and oneof rules, (buf.validate.oneof). A dropped option leaves a short
/* comment */ in the output, and the report lists file, line and rule.

Exit status 0; with --strict, 1 if anything was dropped.
"""

import argparse
import os
import re
import shutil
import sys

# ---------------------------------------------------------------------------
# What nanopb-validate understands: {buf rule: [our rule names]}
# ---------------------------------------------------------------------------

NUMERIC = ('int32', 'int64', 'uint32', 'uint64', 'sint32', 'sint64', 'fixed32', 'fixed64',
           'sfixed32', 'sfixed64', 'float', 'double')
COMPARE = {'const': ['const_value'], 'lt': ['lt'], 'lte': ['lte'], 'gt': ['gt'], 'gte': ['gte'],
           'in': ['in'], 'not_in': ['not_in']}

RULES = {
    'bool': {'const': ['const_value']},
    'string': {'const': ['const_value'], 'len': ['min_len', 'max_len'], 'min_len': ['min_len'],
               'max_len': ['max_len'], 'prefix': ['prefix'], 'suffix': ['suffix'],
               'contains': ['contains'], 'in': ['in'], 'not_in': ['not_in'], 'email': ['email'],
               'hostname': ['hostname'], 'ip': ['ip'], 'ipv4': ['ipv4'], 'ipv6': ['ipv6']},
    'bytes': {'const': ['const_value'], 'len': ['min_len', 'max_len'], 'min_len': ['min_len'],
              'max_len': ['max_len'], 'prefix': ['prefix'], 'suffix': ['suffix'],
              'contains': ['contains'], 'in': ['in'], 'not_in': ['not_in']},
    'enum': {'const': ['const_value'], 'defined_only': ['defined_only'], 'in': ['in'], 'not_in': ['not_in']},
    'repeated': {'min_items': ['min_items'], 'max_items': ['max_items'], 'unique': ['unique']},
    'map': {'min_pairs': ['min_pairs'], 'max_pairs': ['max_pairs']},
    'any': {'in': ['in'], 'not_in': ['not_in']},
    'timestamp': {'lt_now': ['lt_now'], 'gt_now': ['gt_now']},
}
for _type in NUMERIC:
    RULES[_type] = COMPARE

NESTED = {'repeated': ('items',), 'map': ('keys', 'values')}   # their value is a FieldRules
FIELD_KEYS = ('required',)                                     # kept as they are

WHY = {
    'cel': 'CEL expressions are not supported',
    'ignore': 'ignore conditions are not supported',
    'pattern': 'regular expressions are not supported',
    'duration': 'duration rules are not supported',
}


# ---------------------------------------------------------------------------
# Text-format values: {k: v, k {..}, k: [a, b]}
# ---------------------------------------------------------------------------

class Unparsable(Exception):
    pass


def skip_blank(text, i):
    while i < len(text):
        if text[i] in ' \t\r\n':
            i += 1
        elif text.startswith('//', i) or text[i] == '#':
            i = text.find('\n', i)
            i = len(text) if i < 0 else i
        elif text.startswith('/*', i):
            i = text.find('*/', i + 2)
            i = len(text) if i < 0 else i + 2
        else:
            break
    return i


def string_end(text, i):
    """Index after the string literal that starts at text[i]."""
    quote = text[i]
    i += 1
    while i < len(text):
        if text[i] == '\\':
            i += 2
        elif text[i] == quote:
            return i + 1
        else:
            i += 1
    raise Unparsable('unterminated string')


def parse_value(text, i):
    i = skip_blank(text, i)
    if i >= len(text):
        raise Unparsable('value expected')
    if text[i] in '{<':
        close = '}' if text[i] == '{' else '>'
        pairs, i = parse_pairs(text, i + 1, close)
        return ('m', pairs), i
    if text[i] == '[':
        items = []
        i += 1
        while True:
            i = skip_blank(text, i)
            if i < len(text) and text[i] == ']':
                return ('l', items), i + 1
            value, i = parse_value(text, i)
            items.append(value)
            i = skip_blank(text, i)
            if i < len(text) and text[i] == ',':
                i += 1
    if text[i] in '"\'':
        end = string_end(text, i)
        while True:                       # "a" "b" is one string
            j = skip_blank(text, end)
            if j < len(text) and text[j] in '"\'':
                end = string_end(text, j)
            else:
                break
        return ('s', text[i:end]), end
    j = i
    while j < len(text) and text[j] not in ' \t\r\n,;}]>':
        j += 1
    if j == i:
        raise Unparsable('unexpected %r' % text[i])
    return ('s', text[i:j]), j


def parse_pairs(text, i, close):
    pairs = []
    while True:
        i = skip_blank(text, i)
        if i >= len(text):
            raise Unparsable('missing %s' % close)
        if text[i] == close:
            return pairs, i + 1
        if text[i] in ',;':
            i += 1
            continue
        match = re.compile(r'[A-Za-z_][\w.]*|\[[^\]]*\]').match(text, i)
        if not match:
            raise Unparsable('field name expected at %r' % text[i:i + 12])
        key = match.group(0)
        i = skip_blank(text, match.end())
        if i < len(text) and text[i] == ':':
            i += 1
        value, i = parse_value(text, i)
        pairs.append((key, value))


def flatten(pairs, prefix=()):
    """[(path tuple, scalar text)] of a converted tree: one entry per scalar, lists spread out."""
    for key, value in pairs:
        kind, body = value
        if kind == 's':
            yield prefix + (key,), body
        elif kind == 'm':
            for item in flatten(body, prefix + (key,)):
                yield item
        else:
            for sub in body:
                if sub[0] == 's':
                    yield prefix + (key,), sub[1]
                else:
                    for item in flatten([(key, sub)], prefix):
                        yield item


# ---------------------------------------------------------------------------
# buf.validate FieldRules -> ours
# ---------------------------------------------------------------------------

class Report(object):
    def __init__(self):
        self.items = []

    def drop(self, where, rule, why=None):
        self.items.append((where, rule, why or WHY.get(rule.split('.')[-1]) or 'not supported by nanopb-validate'))


def convert_rules(kind, pairs, report, where, path):
    """The rules of one type (string, uint32, repeated, ...)."""
    out = []
    table = RULES.get(kind)
    for key, value in pairs:
        full = '%s.%s' % (path, key)
        if table is not None and key in table:
            out += [(name, value) for name in table[key]]
        elif key in NESTED.get(kind, ()) and value[0] == 'm':
            out.append((key, ('m', convert_field(value[1], report, where, full))))
        elif kind == 'timestamp' and key == 'within' and value[0] == 'm':
            seconds = [(k, v) for k, v in value[1] if k == 'seconds']
            if len(seconds) != len(value[1]):
                report.drop(where, full + '.nanos', 'only whole seconds are supported')
            if seconds:
                out.append(('within', ('m', seconds)))
        else:
            report.drop(where, full)
    return out


def convert_field(pairs, report, where, path='field'):
    """A buf.validate FieldRules message as a list of pairs."""
    out = []
    for key, value in pairs:
        full = '%s.%s' % (path, key)
        if key in FIELD_KEYS:
            out.append((key, value))
        elif key in RULES and value[0] == 'm':
            converted = convert_rules(key, value[1], report, where, full)
            if converted:
                out.append((key, ('m', converted)))
        else:
            report.drop(where, full)
    return out


def option_text(path, scalar):
    return '(validate.rules).%s = %s' % ('.'.join(path), scalar)


# ---------------------------------------------------------------------------
# Scanning the .proto text
# ---------------------------------------------------------------------------

FIELD_OPTION = re.compile(r'^\(\s*\.?buf\.validate\.field\s*\)\s*((?:\.\s*\w+\s*)*)=\s*(.*)$', re.S)
BUF_MESSAGE_OPTION = re.compile(r'option\s*\(\s*\.?buf\.validate\.(message|oneof|field)\s*\)\s*(\.\s*\w+)?')
IDENT = re.compile(r'[A-Za-z0-9_]')


def strip_comments(text):
    out, i = [], 0
    while i < len(text):
        if text[i] in '"\'':
            end = string_end(text, i)
            out.append(text[i:end])
            i = end
        elif text.startswith('//', i):
            i = text.find('\n', i)
            i = len(text) if i < 0 else i
        elif text.startswith('/*', i):
            i = text.find('*/', i + 2)
            i = len(text) if i < 0 else i + 2
            out.append(' ')
        else:
            out.append(text[i])
            i += 1
    return ''.join(out).strip()


def split_options(inner):
    """Split the inside of [ ... ] at top-level commas."""
    parts, depth, start, i = [], 0, 0, 0
    while i < len(inner):
        c = inner[i]
        if c in '"\'':
            i = string_end(inner, i)
            continue
        if inner.startswith('//', i):
            i = inner.find('\n', i)
            i = len(inner) if i < 0 else i
            continue
        if inner.startswith('/*', i):
            i = inner.find('*/', i + 2)
            i = len(inner) if i < 0 else i + 2
            continue
        if c in '{[(<':
            depth += 1
        elif c in '}])>':
            depth -= 1
        elif c == ',' and depth == 0:
            parts.append(inner[start:i])
            start = i + 1
        i += 1
    parts.append(inner[start:])
    return parts


def matching(text, i, open_char, close_char):
    """Index of the bracket that closes the one at text[i]."""
    depth = 0
    while i < len(text):
        c = text[i]
        if c in '"\'':
            i = string_end(text, i)
            continue
        if text.startswith('//', i):
            i = text.find('\n', i)
            i = len(text) if i < 0 else i
            continue
        if text.startswith('/*', i):
            i = text.find('*/', i + 2)
            i = len(text) if i < 0 else i + 2
            continue
        if c == open_char:
            depth += 1
        elif c == close_char:
            depth -= 1
            if depth == 0:
                return i
        i += 1
    raise Unparsable('missing %s' % close_char)


def convert_group(inner, text, start, report, where):
    """The options inside one [ ... ]; returns (new inner text, indent) or None if unchanged."""
    if 'buf.validate' not in inner:
        return None
    options, dropped = [], []
    for part in split_options(inner):
        stripped = strip_comments(part)
        if not stripped:
            continue
        match = FIELD_OPTION.match(stripped)
        if not match:
            if 'buf.validate' in stripped:
                report.drop(where, stripped.split('=')[0].strip(), 'unknown buf.validate option')
                dropped.append(stripped.split('=')[0].strip())
            else:
                options.append(part.strip())
            continue
        path = [p.strip() for p in match.group(1).split('.') if p.strip()]
        try:
            value, end = parse_value(match.group(2), 0)
        except Unparsable as exc:
            report.drop(where, 'field.' + '.'.join(path), 'cannot read the value (%s)' % exc)
            dropped.append('field.' + '.'.join(path))
            continue
        tree = value
        for name in reversed(path):
            tree = ('m', [(name, tree)])
        pairs = tree[1] if tree[0] == 'm' else [('', tree)]
        before = len(report.items)
        converted = convert_field(pairs, report, where)
        dropped += [item[1] for item in report.items[before:]]
        options += [option_text(p, s) for p, s in flatten(converted)]
    return options, dropped


def line_of(text, index):
    return text.count('\n', 0, index) + 1


def convert_text(text, name, report, validate_import):
    out, i, n = [], 0, len(text)
    while i < n:
        c = text[i]
        if text.startswith('//', i):
            j = text.find('\n', i)
            j = n if j < 0 else j
            out.append(text[i:j])
            i = j
        elif text.startswith('/*', i):
            j = text.find('*/', i + 2)
            j = n if j < 0 else j + 2
            out.append(text[i:j])
            i = j
        elif c in '"\'':
            j = string_end(text, i)
            literal = text[i:j]
            if literal[1:-1] == 'buf/validate/validate.proto':
                literal = '%s%s%s' % (c, validate_import, c)
            out.append(literal)
            i = j
        elif c == '[':
            j = matching(text, i, '[', ']')
            inner = text[i + 1:j]
            where = '%s:%d' % (name, line_of(text, i))
            result = convert_group(inner, text, i, report, where)
            if result is None:
                out.append(text[i:j + 1])
            else:
                options, dropped = result
                note = ('/* nanopb-validate: dropped %s */' % ', '.join(sorted(set(dropped)))) if dropped else ''
                if not options:
                    out.append(note)
                else:
                    if '\n' in inner:
                        line_start = text.rfind('\n', 0, i) + 1
                        indent = re.match(r'[ \t]*', text[line_start:i]).group(0)
                        body = ',\n'.join(indent + '    ' + o for o in options)
                        out.append('[\n%s\n%s]%s' % (body, indent, (' ' + note) if note else ''))
                    else:
                        out.append('[%s]%s' % (', '.join(options), (' ' + note) if note else ''))
            i = j + 1
        elif text.startswith('option', i) and (i == 0 or not IDENT.match(text[i - 1])):
            match = BUF_MESSAGE_OPTION.match(text, i)
            if not match:
                out.append(c)
                i += 1
                continue
            j = i
            while j < n and text[j] != ';':
                if text[j] in '"\'':
                    j = string_end(text, j)
                elif text[j] == '{':
                    j = matching(text, j, '{', '}') + 1
                else:
                    j += 1
            what = 'buf.validate.%s%s' % (match.group(1), re.sub(r'\s+', '', match.group(2) or ''))
            report.drop('%s:%d' % (name, line_of(text, i)), what,
                        'message-level rules are not supported' if match.group(1) != 'oneof'
                        else 'oneof rules are not supported')
            out.append('/* nanopb-validate: dropped option (%s) */' % what)
            i = j + 1
        else:
            out.append(c)
            i += 1
    return ''.join(out)


# ---------------------------------------------------------------------------
# Files
# ---------------------------------------------------------------------------

def is_vendored(rel):
    parts = rel.replace('\\', '/').split('/')
    return len(parts) >= 3 and parts[-3:-1] == ['buf', 'validate'] or parts[-3:] == ['buf', 'validate', 'validate.proto']


def convert_file(src, dst, rel, report, validate_import):
    with open(src, encoding='utf-8', newline='') as handle:
        text = handle.read()
    converted = convert_text(text, rel, report, validate_import)
    os.makedirs(os.path.dirname(os.path.abspath(dst)), exist_ok=True)
    with open(dst, 'w', encoding='utf-8', newline='') as handle:
        handle.write(converted)
    return converted != text


def convert_path(source, out, validate_import='validate.proto'):
    """Convert a .proto file or a folder. Returns (Report, [converted files], [copied files])."""
    report, converted, copied = Report(), [], []
    if os.path.isfile(source):
        rel = os.path.basename(source)
        if convert_file(source, os.path.join(out, rel), rel, report, validate_import):
            converted.append(rel)
        return report, converted, copied
    if not os.path.isdir(source):
        raise SystemExit('error: %s is neither a file nor a folder' % source)
    for root, dirs, files in os.walk(source):
        dirs[:] = sorted(d for d in dirs if not d.startswith('.'))
        for name in sorted(files):
            path = os.path.join(root, name)
            rel = os.path.relpath(path, source).replace(os.sep, '/')
            if is_vendored(rel):
                continue
            target = os.path.join(out, *rel.split('/'))
            if name.endswith('.proto'):
                if convert_file(path, target, rel, report, validate_import):
                    converted.append(rel)
            else:
                os.makedirs(os.path.dirname(target), exist_ok=True)
                shutil.copyfile(path, target)
                copied.append(rel)
    return report, converted, copied


def main(argv=None):
    parser = argparse.ArgumentParser(description='Convert protovalidate (buf.validate) options to nanopb-validate.')
    parser.add_argument('source', help='a .proto file or a folder of .proto files')
    parser.add_argument('--out', required=True, help='folder for the converted files (never the source folder)')
    parser.add_argument('--validate-import', default='validate.proto', metavar='PATH',
                        help='what replaces import "buf/validate/validate.proto" (default: validate.proto; '
                             'use validate/validate.proto if your folders carry that copy)')
    parser.add_argument('--strict', action='store_true', help='exit 1 if any rule had to be dropped')
    args = parser.parse_args(argv)

    if os.path.abspath(args.out) == os.path.abspath(args.source):
        parser.error('--out must be a different folder than the source: the original is never modified')
    report, converted, copied = convert_path(args.source, args.out, args.validate_import)

    print('converted %d file(s) into %s' % (len(converted), args.out))
    if copied:
        print('copied unchanged: %d file(s)' % len(copied))
    if report.items:
        print('\nnot converted (nanopb-validate cannot enforce these):')
        for where, rule, why in report.items:
            print('  %-28s %-34s %s' % (where, rule, why))
    return 1 if (args.strict and report.items) else 0


if __name__ == '__main__':
    sys.exit(main())
