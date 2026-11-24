#!/usr/bin/env python3
"""Add nanopb-validate's (validate.rules) next to protovalidate's (buf.validate) annotations.

One file, Python 3 standard library only, no import from nanopb_validate.

    python buf_to_validate.py PROTOS                       # in place: only additions
    python buf_to_validate.py PROTOS --backup              # ... keeping <file>.proto.bak first
    python buf_to_validate.py PROTOS --out CONVERTED       # into another folder
    python buf_to_validate.py PROTOS --out CONVERTED --replace      # the old behaviour

PROTOS is a project folder of .proto files (or one .proto file). In place, only the
.proto files that get something added are rewritten; buf's own buf/validate/*, every
other file and every original line stay as they are, and a second run changes
nothing. With --out the result goes to CONVERTED (same relative paths) and the
project is not touched.

Append mode (the default) keeps the buf setup and adds ours, field by field,
keeping comments and layout:

    import "buf/validate/validate.proto";                 stays
                                                          + import "buf/validate/validate_rules.proto";
    string name = 1 [(buf.validate.field).string.max_len = 20];
        -> string name = 1 [(buf.validate.field).string.max_len = 20,
                            (validate.rules).string.max_len = 20, (nanopb).max_length = 20];
                                                          + import "nanopb.proto";

    const -> const_value;   len -> min_len + max_len (strings and bytes)

Our validate.proto is added as validate_rules.proto (--validate-name): next to buf's
validate.proto when the project has it, else at the top of the project; each file
that uses rules imports both: buf keeps working, nanopb-validate enforces its part. Fields
that buf limits get nanopb sizes, so they are static storage instead of
pb_callback_t: string max_len/len/const/in/email/... -> (nanopb).max_length (the
longest string; nanopb adds the NUL), bytes -> max_size, repeated max_items / map
max_pairs -> (nanopb).max_count; never where a size is already set (inline, the
.options file, or file-wide). A field the rules give no limit for is listed in the
report. A file that uses (nanopb) options imports nanopb.proto; the project gets a
nanopb.proto next to our rules file if it has none. Imports of buf's validate.proto,
our rules file and nanopb.proto follow what each file uses: missing ones are added,
unused ones removed. --no-sizes turns the sizes off. Our rules file and
nanopb.proto go next to every buf validate.proto of the project (at the top without
one), imported the way the file imports buf's ("buf/validate/validate_rules.proto").

Rules nanopb-validate cannot enforce are listed (file, line, rule), never
converted into something that only looks equivalent: cel, ignore, pattern,
*_bytes, uri/uuid/... formats, absolute timestamp bounds, duration rules,
message-level cel and oneof rules, (buf.validate.oneof). When appending they
stay in the file for buf; with --replace they are dropped and leave a short
/* comment */.

Exit status 0; with --strict, 1 if any rule is not enforced by nanopb-validate.
"""

import argparse
import fnmatch
import os
import re
import shutil
import sys

DEFAULT_NAME = 'validate_rules.proto'
_HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_VALIDATE_PROTO = os.path.join(_HERE, '..', 'nanopb_validate', 'validate_proto', 'validate.proto')
DEFAULT_NANOPB_PROTO = os.path.join(_HERE, '..', '..', 'generator', 'proto', 'nanopb.proto')

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


def last_code_end(inner):
    """Index just after the last character of ``inner`` that is code, not blank or comment."""

    end, i = 0, 0
    while i < len(inner):
        c = inner[i]
        if c in '"\'':
            i = string_end(inner, i)
            end = i
            continue
        if inner.startswith('//', i):
            j = inner.find('\n', i)
            i = len(inner) if j < 0 else j
            continue
        if inner.startswith('/*', i):
            j = inner.find('*/', i + 2)
            i = len(inner) if j < 0 else j + 2
            continue
        if c not in ' \t\r\n':
            end = i + 1
        i += 1
    return end


def convert_group(inner, report, where, append=False):
    """The options inside one [ ... ]: (kept, added, dropped, buf_rules), or None without buf.validate.

    kept      the original options that stay: every one when appending, else the non-buf ones
    added     the (validate.rules) options for the buf rules nanopb-validate can enforce
    dropped   the buf rules it cannot enforce (reported)
    buf_rules the buf FieldRules as (key, value) pairs, for the nanopb sizes
    """

    if 'buf.validate' not in inner:
        return None
    kept, added, dropped, buf_rules = [], [], [], []
    for part in split_options(inner):
        stripped = strip_comments(part)
        if not stripped:
            continue
        match = FIELD_OPTION.match(stripped)
        if not match:
            if 'buf.validate' in stripped:
                name = stripped.split('=')[0].strip()
                report.drop(where, name, 'unknown buf.validate option')
                dropped.append(name)
                if append:
                    kept.append(part.strip())
            else:
                kept.append(part.strip())
            continue
        if append:
            kept.append(part.strip())
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
        buf_rules += pairs
        before = len(report.items)
        converted = convert_field(pairs, report, where)
        dropped += [item[1] for item in report.items[before:]]
        added += [option_text(p, s) for p, s in flatten(converted)]
    if append:
        # Run again on its own output: what is already there is not added twice.
        present = set(re.sub(r'\s+', '', strip_comments(p)) for p in split_options(inner))
        added = [o for o in added if re.sub(r'\s+', '', o) not in present]
    return kept, added, dropped, buf_rules


# ---------------------------------------------------------------------------
# nanopb sizes from the buf limits: static storage instead of pb_callback_t
# ---------------------------------------------------------------------------

# Longest value of a well-known string format, in bytes.
STRING_FORMATS = {'email': 254, 'hostname': 253, 'ip': 45, 'ipv4': 15, 'ipv6': 45, 'uuid': 36, 'tuuid': 32}
LENGTH_KEYS = {'string': ('max_len', 'len', 'max_bytes', 'len_bytes'), 'bytes': ('max_len', 'len')}


def literal_length(token):
    """Bytes in a protobuf string literal ("ab\\x01" -> 3), or None if it is not one."""

    if len(token) < 2 or token[0] not in '"\'' or token[-1] != token[0]:
        return None
    body, i, n = token[1:-1], 0, 0
    while i < len(body):
        if body[i] == '\\' and i + 1 < len(body):
            nxt = body[i + 1]
            if nxt in 'xX':
                i += 2
                digits = 0
                while i < len(body) and digits < 2 and body[i] in '0123456789abcdefABCDEF':
                    i += 1
                    digits += 1
            elif nxt in '01234567':
                i += 1
                digits = 0
                while i < len(body) and digits < 3 and body[i] in '01234567':
                    i += 1
                    digits += 1
            elif nxt in 'uU':
                width = 4 if nxt == 'u' else 8
                code = int(body[i + 2:i + 2 + width] or '0', 16)
                i += 2 + width
                n += len(chr(code).encode('utf-8')) - 1 if code < 0x110000 else 0
            else:
                i += 2
        else:
            n += len(body[i].encode('utf-8')) - 1
            i += 1
        n += 1
    return n


def scalar_int(value):
    if value[0] != 's':
        return None
    try:
        return int(value[1], 0)
    except ValueError:
        return None


def merged(pairs):
    """{key: [sub pairs]} of the message values in ``pairs`` (one option may be split in many)."""

    result = {}
    for key, value in pairs:
        if value[0] == 'm':
            result.setdefault(key, []).extend(value[1])
    return result


def longest_value(kind, pairs):
    """The most bytes a string or bytes field can hold under these buf rules, or None."""

    bounds = []
    for key, value in pairs:
        if key in LENGTH_KEYS[kind]:
            if scalar_int(value) is not None:
                bounds.append(scalar_int(value))
        elif key == 'const' and value[0] == 's' and literal_length(value[1]) is not None:
            bounds.append(literal_length(value[1]))
        elif key == 'in':
            items = value[1] if value[0] == 'l' else [value]
            lengths = [literal_length(item[1]) for item in items if item[0] == 's']
            if lengths and None not in lengths:
                bounds.append(max(lengths))
        elif kind == 'string' and key in STRING_FORMATS and value == ('s', 'true'):
            bounds.append(STRING_FORMATS[key])
    return min(bounds) if bounds else None


def nanopb_sizes(buf_rules):
    """[(nanopb option, value)] that give a field static storage: max_length for strings
    (the longest string, nanopb adds the NUL), max_size for bytes, max_count for repeated
    fields and maps."""

    rules, out = merged(buf_rules), []

    def size_of(kind, pairs):
        n = longest_value(kind, pairs)
        if n is not None:
            out.append(('max_length', n) if kind == 'string' else ('max_size', n))

    for kind in ('string', 'bytes'):
        if kind in rules:
            size_of(kind, rules[kind])
    if 'repeated' in rules:
        for key, value in rules['repeated']:
            if key == 'max_items' and scalar_int(value):
                out.append(('max_count', scalar_int(value)))
        items = merged(rules['repeated']).get('items')
        if items:
            for kind, pairs in merged(items).items():
                if kind in LENGTH_KEYS:
                    size_of(kind, pairs)
    if 'map' in rules:
        for key, value in rules['map']:
            if key == 'max_pairs' and scalar_int(value):
                out.append(('max_count', scalar_int(value)))
    seen, result = set(), []
    for option, value in out:
        if option not in seen:
            seen.add(option)
            result.append((option, value))
    return result


class Sizes(object):
    """What already sizes the fields of one file: its .options file and file-level options."""

    def __init__(self, options_text='', file_text=''):
        self.lines = []
        for line in options_text.splitlines():
            line = line.split('#', 1)[0].split('//', 1)[0].strip()
            if line:
                parts = line.split(None, 1)
                self.lines.append((parts[0], parts[1] if len(parts) > 1 else ''))
        self.file_wide = set(re.findall(r'\(\s*nanopb_fileopt\s*\)\s*\.\s*(\w+)', strip_comments(file_text)))

    def has(self, option, full_name, inner):
        """True if the field already has ``option`` (max_size and max_length both size it)."""

        names = ('max_size', 'max_length') if option in ('max_size', 'max_length') else (option,)
        group = '|'.join(names + ('type',))
        code = strip_comments(inner)
        if re.search(r'\(\s*nanopb\s*\)\s*\.\s*(%s)\b' % group, code) or \
                re.search(r'\(\s*nanopb\s*\)\s*=', code):
            return True
        if any(name in self.file_wide for name in names):
            return True
        short = full_name.split('.', 1)[1] if '.' in full_name else full_name
        for pattern, settings in self.lines:
            if (fnmatch.fnmatchcase(full_name, pattern) or fnmatch.fnmatchcase(short, pattern)) and \
                    re.search(r'\b(%s)\s*:' % group, settings):
                return True
        return False


FIELD_DECL = re.compile(r'(?:^|[;{}])\s*(?:(repeated|optional|required)\s+)?(map\s*<[^>]*>|\.?[\w.]+)\s+(\w+)\s*=\s*\d+\s*$',
                        re.S)
MESSAGE_OPEN = re.compile(r'(?:^|[;{}\s])message\s+(\w+)\s*$')
PACKAGE = re.compile(r'^\s*package\s+([\w.]+)\s*;', re.M)


def code_mask(text):
    """``text`` with every comment and string literal replaced by spaces (newlines kept), so
    indexes stay the same and a look back from any position sees only code. Never raises:
    an apostrophe in a comment (// don't) is inside the comment, and an unterminated
    literal ends at its line."""

    out, i, n = list(text), 0, len(text)

    def blank(a, b):
        for k in range(a, b):
            if out[k] != '\n':
                out[k] = ' '

    while i < n:
        if text.startswith('//', i):
            j = text.find('\n', i)
            j = n if j < 0 else j
            blank(i, j)
            i = j
        elif text.startswith('/*', i):
            j = text.find('*/', i + 2)
            j = n if j < 0 else j + 2
            blank(i, j)
            i = j
        elif text[i] in '"\'':
            quote, j = text[i], i + 1
            while j < n and text[j] != quote and text[j] != '\n':
                j += 2 if text[j] == '\\' else 1
            j = min(j + 1, n)
            blank(i, j)
            i = j
        else:
            i += 1
    return ''.join(out)


def declared_field(code, i):
    """(label, type, name) of the field whose options start at code[i] ('['), or None
    (``code`` is the file's code_mask)."""

    start = max(code.rfind(';', 0, i), code.rfind('{', 0, i), code.rfind('}', 0, i))
    match = FIELD_DECL.search(code[start if start >= 0 else 0:i].rstrip())
    return (match.group(1) or '', re.sub(r'\s+', '', match.group(2)), match.group(3)) if match else None


def needed_sizes(label, type_name):
    """The nanopb options a field of that label and type needs for static storage."""

    needed = []
    if type_name in ('string', 'bytes') or (type_name.startswith('map<') and 'string' in type_name):
        needed.append('max_length' if type_name == 'string' else 'max_size')
    if label == 'repeated' or type_name.startswith('map<'):
        needed.append('max_count')
    return needed


# ---------------------------------------------------------------------------
# One .proto file
# ---------------------------------------------------------------------------

class FileState(object):
    """Per file: replace or append, what it imports, which nanopb sizes were added."""

    def __init__(self, append=False, sizes=None, package=''):
        self.append = append
        self.sizes = sizes            # a Sizes, or None to add no nanopb options
        self.package = package
        self.buf_imports = []
        self.sized = []               # (field, option, value)
        self.unsized = []             # (field, option): no limit in the rules to size it from


def line_of(text, index):
    return text.count('\n', 0, index) + 1


def is_buf_import(name):
    return name == 'buf/validate/validate.proto' or name.endswith('/buf/validate/validate.proto')


def convert_text(text, name, report, validate_import, append=False, state=None):
    """Convert one file's text. ``validate_import`` replaces buf's import (replace mode);
    when appending, buf's import stays."""

    state = state or FileState(append)
    state.append = append
    code = code_mask(text)
    package = PACKAGE.search(code)
    state.package = package.group(1) if package else ''
    out, i, n = [], 0, len(text)
    scopes = []                       # message names, None for any other { }
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
            # buf's validate.proto, also from a vendored path (third_party/buf/validate/validate.proto)
            if is_buf_import(literal[1:-1]):
                state.buf_imports.append(literal[1:-1])
                if not append:
                    literal = '%s%s%s' % (c, validate_import, c)
            out.append(literal)
            i = j
        elif c == '{':
            message = MESSAGE_OPEN.search(code[max(0, i - 200):i].rstrip())
            scopes.append(message.group(1) if message else None)
            out.append(c)
            i += 1
        elif c == '}':
            if scopes:
                scopes.pop()
            out.append(c)
            i += 1
        elif c == '[':
            j = matching(text, i, '[', ']')
            inner = text[i + 1:j]
            where = '%s:%d' % (name, line_of(text, i))
            result = convert_group(inner, report, where, append)
            if result is None:
                out.append(text[i:j + 1])
                i = j + 1
                continue
            kept, added, dropped, buf_rules = result
            decl = declared_field(code, i)
            messages = [s for s in scopes if s]       # a oneof's braces are not a message
            if state.sizes is not None and decl and messages:
                label, type_name, field = decl
                full = '.'.join(([state.package] if state.package else []) + messages + [field])
                given = set()
                for option, value in nanopb_sizes(buf_rules):
                    if not state.sizes.has(option, full, inner):
                        added.append('(nanopb).%s = %d' % (option, value))
                        state.sized.append((full, option, value))
                    given.add(option)
                # What the rules give no number for: the report names it (else a pb_callback_t).
                for option in needed_sizes(label, type_name):
                    if option not in given and not state.sizes.has(option, full, inner):
                        state.unsized.append((full, option))
            what = 'not enforced by nanopb-validate (kept for buf)' if append else 'dropped'
            note = ('/* nanopb-validate: %s %s */' % (what, ', '.join(sorted(set(dropped))))) if dropped else ''
            multiline = '\n' in inner
            line_start = text.rfind('\n', 0, i) + 1
            indent = re.match(r'[ \t]*', text[line_start:i]).group(0)
            if append:
                # The original text stays exactly as it was; ours goes after its last option.
                # A note already written by an earlier run is not written again.
                if note and text[j + 1:].lstrip(' \t').startswith(note):
                    note = ''
                end = last_code_end(inner)
                if multiline and added:
                    # A comma right after the last option (before its comment, which stays on
                    # that line), then each of ours on a line of its own, indented like it.
                    pos = inner.find('\n', end)
                    pos = len(inner) if pos < 0 else pos
                    option_line = inner.rfind('\n', 0, end) + 1
                    if option_line == 0:            # the last option is on the line of the '['
                        option_indent = indent + '    '
                    else:
                        option_indent = re.match(r'[ \t]*', inner[option_line:]).group(0)
                    lines = ''.join('\n%s%s%s' % (option_indent, o, ',' if k < len(added) - 1 else '')
                                    for k, o in enumerate(added))
                    out.append('[%s,%s%s%s]%s' % (inner[:end], inner[end:pos], lines, inner[pos:],
                                                  (' ' + note) if note else ''))
                elif multiline:
                    out.append('[%s]%s' % (inner, (' ' + note) if note else ''))
                else:
                    extra = ''.join(', %s' % o for o in added)
                    out.append('[%s%s%s]%s' % (inner[:end], extra, inner[end:], (' ' + note) if note else ''))
            else:
                options = kept + added
                if not options:
                    out.append(note)
                elif multiline:
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
            why = 'message-level rules are not supported' if match.group(1) != 'oneof' else 'oneof rules are not supported'
            report.drop('%s:%d' % (name, line_of(text, i)), what, why + (' (kept for buf)' if append else ''))
            if append:
                out.append(text[i:j + 1])
            else:
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


# import "a.proto";  or  import 'a.proto';  (group 2 is the name)
IMPORT_RE = re.compile(r'''^[ \t]*import\s+(?:public\s+|weak\s+)?(["'])([^"'\n]+)\1\s*;[^\n]*\n?''', re.M)
PACKAGE_RE = re.compile(r'^\s*package\s+[\w.]+\s*;[^\n]*\n?', re.M)
SYNTAX_RE = re.compile(r'''^\s*(?:syntax|edition)\s*=\s*["'][^"']*["']\s*;[^\n]*\n?''', re.M)

# Names of our rules file written by earlier versions of this script.
OLD_NAMES = ('nanopb_validate.proto',)
# What makes a file our rules file: (validate.rules) is FieldOptions extension 1011.
OUR_RULES_RE = re.compile(r'extend\s+\.?(?:google\.protobuf\.)?FieldOptions\s*\{[^}]*=\s*1011\s*;', re.S)


def imports_of(text):
    """[(match, name)] of the import lines of ``text`` that are code (not in a comment)."""

    code = code_mask(text)
    return [(m, m.group(2)) for m in IMPORT_RE.finditer(text)
            if code[m.start():m.end()].lstrip().startswith('import')]


def import_kind(name, validate_import, roots):
    """'buf', 'ours' (our rules file, under any name), 'old' (an earlier version's name of
    ours) or 'other'."""

    base = name.rsplit('/', 1)[-1]
    if is_buf_import(name):
        return 'buf'
    if name == validate_import or base == os.path.basename(validate_import):
        return 'ours'
    if base in OLD_NAMES:
        return 'old'
    for root in roots:
        path = os.path.join(root, *name.split('/'))
        if os.path.isfile(path):
            return 'ours' if OUR_RULES_RE.search(strip_comments(read_text(path))) else 'other'
    # Not in the project: "validate.proto" is the copy nanopb_validate provides itself.
    return 'ours' if name == 'validate.proto' else 'other'


def add_import(text, name):
    line = 'import "%s";\n' % name
    anchors = [m for m, _ in imports_of(text)] or list(PACKAGE_RE.finditer(text)) or list(SYNTAX_RE.finditer(text))
    if anchors:
        end = anchors[-1].end()
        if not text[:end].endswith('\n'):
            line = '\n' + line
        return text[:end] + line + text[end:]
    return line + text


def ensure_validate_import(text, validate_import, roots=(), changes=None):
    """Add  import "<validate_import>";  to a file that uses (validate.rules) or (validate.message)
    without importing our rules file: protoc otherwise stops with
    'Option "(validate.rules)" unknown'. Only an import of our rules file counts (by name, or
    a file in ``roots`` that defines them); buf's validate.proto or any other *validate.proto
    does not. An import of an earlier version's name (nanopb_validate.proto) is switched to
    ``validate_import``: both define the same rules, so protoc refuses the two together."""

    code = strip_comments(text)
    if '(validate.rules)' not in code and '(validate.message)' not in code:
        return text
    uses_buf = bool(BUF_OPTION_RE.search(code))
    for match, name in imports_of(text):
        if name.rsplit('/', 1)[-1] in OLD_NAMES:
            if changes is not None:
                changes.append('import "%s" -> "%s"' % (name, validate_import))
            return text[:match.start(2)] + validate_import + text[match.end(2):]
        if option_import_kind(name, validate_import, roots, uses_buf) == 'ours':
            return text                       # our rules file, under any name
    return add_import(text, validate_import)


BUF_OPTION_RE = re.compile(r'\(\s*\.?buf\.validate\.')
OUR_OPTION_RE = re.compile(r'\(\s*\.?validate\.(?:rules|message|validate)\s*\)')
NANOPB_OPTION_RE = re.compile(r'\(\s*\.?nanopb(?:_fileopt|_msgopt|_enumopt)?\s*\)')
_BUF_PACKAGE_RE = re.compile(r'^\s*package\s+buf\.validate\s*;', re.M)


def resolve_import(name, roots):
    """The file an import names, in the first of ``roots`` that has it, or None."""

    for root in roots:
        path = os.path.join(root, *name.split('/'))
        if os.path.isfile(path):
            return path
    return None


def option_import_kind(name, validate_import, roots, uses_buf=False):
    """'buf', 'ours' or 'nanopb' for an import of one of the option files this script
    handles, under any name, else None: any other import is never added or removed.

    The file is found in the project (``roots``: every folder of it) and told by its
    content: package buf.validate is buf's, (validate.rules) at 1011 is ours. Not in the
    project: buf/validate/validate.proto is buf's; another .../validate.proto is buf's in a
    file that uses buf options (it comes from the buf setup), else ours (the copy
    nanopb_validate provides)."""

    base = name.rsplit('/', 1)[-1]
    if base == 'nanopb.proto':
        return 'nanopb'
    if base in OLD_NAMES or (validate_import and base == os.path.basename(validate_import)):
        return 'ours'
    path = resolve_import(name, roots)
    if path:
        text = read_text(path)
        if _BUF_PACKAGE_RE.search(code_mask(text)):
            return 'buf'
        if OUR_RULES_RE.search(strip_comments(text)):
            return 'ours'
        return None
    if is_buf_import(name):
        return 'buf'
    if base == 'validate.proto':
        return 'buf' if uses_buf else 'ours'
    return None


def buf_import_of(text, roots):
    """The name under which ``text`` imports buf's validate.proto, or None."""

    for _, name in imports_of(text):
        if option_import_kind(name, '', roots, uses_buf=True) == 'buf':
            return name
    return None


def ensure_buf_import(text, buf_import, roots):
    """Add  import "<buf_import>";  to a file that uses (buf.validate...) options without
    importing buf's validate.proto (under any name)."""

    if not BUF_OPTION_RE.search(strip_comments(text)):
        return text
    if buf_import_of(text, roots):
        return text
    return add_import(text, buf_import)


def remove_unused_imports(text, validate_import, roots, removed=None):
    """Remove the imports of buf's validate.proto, our rules file and nanopb.proto from a file
    that uses none of their options (protoc warns "Import ... is unused"). Every other import,
    and an `import public`, stays."""

    code = strip_comments(text)
    used = {'buf': BUF_OPTION_RE.search(code), 'ours': OUR_OPTION_RE.search(code),
            'nanopb': NANOPB_OPTION_RE.search(code)}
    for match, name in reversed(imports_of(text)):
        if re.match(r'\s*import\s+public\b', match.group(0)):
            continue
        kind = option_import_kind(name, validate_import, roots, bool(used['buf']))
        if kind and not used[kind]:
            text = text[:match.start()] + text[match.end():]
            if removed is not None:
                removed.append(name)
    return text


def uses_validation(text):
    """True for a file with buf.validate or (validate.rules) options."""

    code = strip_comments(text)
    return bool(BUF_OPTION_RE.search(code) or OUR_OPTION_RE.search(code))


def ensure_nanopb_import(text, name='nanopb.proto', always=False):
    """Add  import "<name>";  to a file that uses (nanopb) options, or with ``always`` to any
    file, without importing a nanopb.proto (any one it already imports is kept)."""

    code = strip_comments(text)
    if not always and not re.search(r'\(\s*nanopb(_fileopt|_msgopt|_enumopt)?\s*\)', code):
        return text
    if any(n == 'nanopb.proto' or n.endswith('/nanopb.proto') for _, n in imports_of(text)):
        return text
    return add_import(text, name)


def read_text(path):
    try:
        with open(path, encoding='utf-8', newline='') as handle:
            return handle.read()
    except OSError:
        return ''




class Options(object):
    """How convert_path works; the defaults are append mode with nanopb sizes."""

    def __init__(self, append=True, validate_import='validate.proto', validate_name=DEFAULT_NAME,
                 sizes=True, validate_proto=None, nanopb_proto=None, backup=False):
        self.append = append
        self.validate_import = validate_import      # replace mode: what replaces buf's import
        self.validate_name = validate_name          # append mode: our rules file
        self.sizes = sizes
        self.validate_proto = validate_proto or DEFAULT_VALIDATE_PROTO
        self.nanopb_proto = nanopb_proto or DEFAULT_NANOPB_PROTO
        self.backup = backup                        # in place: keep <file>.proto.bak
        # Set by convert_path:
        self.buf_dirs = []                          # folders holding buf's validate.proto ('' = top)
        self.nanopb_files = []                      # nanopb.proto files the project already has
        self.roots = []                             # folders imports may be relative to
        self.buf_files = []                         # buf validate.proto files of the project


BUF_PACKAGE_RE = re.compile(r'^\s*package\s+buf\.validate\s*;', re.M)


def is_buf_validate(base, rel):
    """True for protovalidate's own files: under buf/validate/, or any .proto of package
    buf.validate (a vendored copy in another folder or under another name)."""

    if is_vendored(rel):
        return True
    if not rel.endswith('.proto'):
        return False
    return bool(BUF_PACKAGE_RE.search(code_mask(read_text(os.path.join(base, *rel.split('/'))))))


def folder_of(name):
    return name.rsplit('/', 1)[0] if '/' in name else ''


def support_import(state, opts, filename):
    """How this file imports one of the files we add (our rules file, nanopb.proto): from the
    folder its buf import names, when the project holds buf's validate.proto
    ("buf/validate/validate_rules.proto"); else from the top ("validate_rules.proto")."""

    if not opts.buf_dirs:
        return filename
    if state.buf_imports:
        folder = folder_of(state.buf_imports[0])
    else:
        folder = opts.buf_dirs[0]
    return (folder + '/' if folder else '') + filename


def buf_import_name(opts):
    """How a file that misses it imports buf's validate.proto: "buf/validate/validate.proto"
    (the protovalidate name), or the project path of a copy stored under another name."""

    for rel in opts.buf_files:
        if rel.endswith('buf/validate/validate.proto'):
            return 'buf/validate/validate.proto'
    return opts.buf_files[0] if opts.buf_files else 'buf/validate/validate.proto'


def nanopb_import(state, opts):
    """The nanopb.proto this file imports: one the project already has (two copies in one
    compile define everything twice), else the one we add next to our rules file."""

    if opts.nanopb_files:
        wanted = support_import(state, opts, 'nanopb.proto')
        for rel in opts.nanopb_files:
            if rel == wanted or rel.endswith('/' + wanted):
                return wanted
        if 'nanopb.proto' in opts.nanopb_files:
            return 'nanopb.proto'
        return opts.nanopb_files[0]
    return support_import(state, opts, 'nanopb.proto')


def convert_file(src, dst, rel, report, opts, result):
    """Convert one file; a file it cannot read is left (copied) unchanged and listed in
    result.failed (the others are still converted)."""

    try:
        return _convert_file(src, dst, rel, report, opts, result)
    except Unparsable as exc:
        result.failed.append((rel, str(exc)))
        if os.path.abspath(src) != os.path.abspath(dst):
            os.makedirs(os.path.dirname(os.path.abspath(dst)), exist_ok=True)
            shutil.copyfile(src, dst)
        return False


def _convert_file(src, dst, rel, report, opts, result):
    text = read_text(src)
    options_text = read_text(os.path.splitext(src)[0] + '.options')
    state = FileState(opts.append, Sizes(options_text, text) if opts.sizes else None)
    converted = convert_text(text, rel, report, opts.validate_import, opts.append, state)
    roots = [os.path.dirname(os.path.abspath(src))] + opts.roots
    if opts.append:
        # buf options without buf's import: add it (our imports are named after it).
        before = converted
        converted = ensure_buf_import(converted, buf_import_name(opts), roots)
        if converted != before:
            result.imports_added.append('%s: %s' % (rel, buf_import_name(opts)))
        # Our imports are named like the file's own import of buf's validate.proto, whatever
        # name that has ("protovalidate/validate.proto" -> "protovalidate/validate_rules.proto").
        existing = buf_import_of(converted, roots)
        if existing:
            state.buf_imports[:] = [existing]
    validate_import = support_import(state, opts, opts.validate_name) if opts.append else opts.validate_import
    changes = []
    converted = ensure_validate_import(converted, validate_import, roots, changes)
    result.migrated += ['%s: %s' % (rel, c) for c in changes]
    nanopb_name = nanopb_import(state, opts) if opts.append else 'nanopb.proto'
    converted = ensure_nanopb_import(converted, nanopb_name)
    removed = []
    converted = remove_unused_imports(converted, validate_import, roots, removed)
    result.imports_removed += ['%s: %s' % (rel, name) for name in removed]
    names = [name for _, name in imports_of(converted)]
    if validate_import in names:
        result.validate_imports.add(validate_import)
    if nanopb_name in names:
        result.nanopb_imports.add(nanopb_name)
    if state.sized:
        result.sized += [(rel,) + s for s in state.sized]
    result.unsized += [(rel,) + s for s in state.unsized]
    in_place = os.path.abspath(src) == os.path.abspath(dst)
    if in_place and converted == text:
        return False                              # nothing to add: the file is not touched
    if in_place and opts.backup and not os.path.exists(src + '.bak'):
        shutil.copyfile(src, src + '.bak')
        result.backups.append(rel + '.bak')
    os.makedirs(os.path.dirname(os.path.abspath(dst)), exist_ok=True)
    with open(dst, 'w', encoding='utf-8', newline='') as handle:
        handle.write(converted)
    return converted != text


class Result(object):
    def __init__(self):
        self.report = Report()
        self.converted, self.copied, self.written, self.backups = [], [], [], []
        self.sized = []                  # (file, field, option, value)
        self.failed = []                 # (file, why): left unchanged
        self.unsized = []                # (file, field, option): rules give no number for it
        self.imports_added = []          # "file: name" of buf imports added
        self.imports_removed = []        # "file: name" of unused option imports removed
        self.migrated = []               # "file: import "old" -> "new""
        self.validate_imports = set()    # how files import our rules file
        self.nanopb_imports = set()      # how files import nanopb.proto
        self.in_place = False

    @property
    def uses_nanopb(self):
        return bool(self.nanopb_imports)

    def __iter__(self):                  # report, converted, copied = convert_path(...)
        return iter((self.report, self.converted, self.copied))


def copy_support_file(source, out, rel, result, what):
    target = os.path.join(out, *rel.split('/'))
    if os.path.exists(target):
        return
    if not os.path.isfile(source):
        raise SystemExit('error: %s not found (%s); give its path with --%s-proto'
                         % (source, rel, what))
    os.makedirs(os.path.dirname(target), exist_ok=True)
    shutil.copyfile(source, target)
    result.written.append(rel)


def list_files(source):
    """'/'-separated paths of the files below ``source`` (hidden folders skipped)."""

    found = []
    for root, dirs, files in os.walk(source):
        dirs[:] = sorted(d for d in dirs if not d.startswith('.'))
        for name in sorted(files):
            found.append(os.path.relpath(os.path.join(root, name), source).replace(os.sep, '/'))
    return found


def support_locations(import_names, buf_dirs):
    """Where the files we add go: next to every buf validate.proto of the project, and for an
    import whose folder matches none of them, that folder (from the top of the project)."""

    locations = list(buf_dirs)
    for name in sorted(import_names):
        folder = folder_of(name)
        if any(d == folder or (folder and d.endswith('/' + folder)) or (not folder and buf_dirs)
               for d in locations):
            continue
        locations.append(folder)
    return locations or ['']


def convert_path(source, out=None, validate_import='validate.proto', opts=None):
    """Convert a .proto file or a folder, into ``out`` or, without it (or with out ==
    source), in place: only .proto files that get something added are rewritten, nothing
    else is touched. Returns a Result, which also unpacks as (Report, [converted files],
    [copied files])."""

    opts = opts or Options(validate_import=validate_import)
    result = Result()
    if os.path.isfile(source):
        base = os.path.dirname(os.path.abspath(source))
        source_files = [os.path.basename(source)]
    elif os.path.isdir(source):
        base = source
        source_files = list_files(source)
    else:
        raise SystemExit('error: %s is neither a file nor a folder' % source)
    out = out or base
    result.in_place = os.path.abspath(out) == os.path.abspath(base)
    if result.in_place and not opts.append:
        raise SystemExit('error: --replace needs --out: it removes the buf.validate options, so it never '
                         'works in place')
    # buf's validate.proto wherever the project has it (buf/validate/validate.proto,
    # third_party/buf/validate/validate.proto, a copy of package buf.validate in another
    # folder): our rules file and nanopb.proto go next to each one.
    buf_files = [r for r in source_files if is_buf_validate(base, r)]
    opts.buf_dirs = sorted(set(folder_of(r) for r in buf_files if r.endswith('.proto')))
    opts.buf_files = [r for r in buf_files if r.endswith('.proto')]
    ours = opts.validate_name if opts.append else None
    opts.nanopb_files = [r for r in source_files if r.rsplit('/', 1)[-1] == 'nanopb.proto']
    # An import may be relative to any folder of the project (whatever -I the build uses):
    # the top first, then shallower folders before deeper ones.
    folders = set([''])
    for r in source_files:
        parts = r.split('/')[:-1]
        for k in range(1, len(parts) + 1):
            folders.add('/'.join(parts[:k]))
    opts.roots = [os.path.abspath(os.path.join(base, *f.split('/'))) if f else os.path.abspath(base)
                  for f in sorted(folders, key=lambda f: (f.count('/') + (1 if f else 0), f))]

    for rel in source_files:
        path = os.path.join(base, *rel.split('/'))
        target = os.path.join(out, *rel.split('/'))
        if rel in buf_files or rel.rsplit('/', 1)[-1] in (ours, 'nanopb.proto'):
            # buf's own files, our rules file and nanopb.proto stay as they are.
            if not result.in_place and opts.append:
                os.makedirs(os.path.dirname(target), exist_ok=True)
                shutil.copyfile(path, target)
                result.copied.append(rel)
            continue
        if rel.endswith('.proto'):
            if convert_file(path, target, rel, result.report, opts, result):
                result.converted.append(rel)
        elif not result.in_place and not rel.endswith('.proto.bak'):
            os.makedirs(os.path.dirname(target), exist_ok=True)
            shutil.copyfile(path, target)
            result.copied.append(rel)
    if opts.append and result.validate_imports:
        for folder in support_locations(result.validate_imports, opts.buf_dirs):
            copy_support_file(opts.validate_proto, out, (folder + '/' if folder else '') + opts.validate_name,
                              result, 'validate')
    if opts.append and not opts.nanopb_files:
        # A project without nanopb.proto gets one: next to our rules file, i.e. next to every
        # buf validate.proto, or at the top (nanopb's generator also brings its own copy, but
        # it is used only when a file imports "nanopb.proto" by that name).
        for folder in support_locations(result.nanopb_imports, opts.buf_dirs):
            copy_support_file(opts.nanopb_proto, out, (folder + '/' if folder else '') + 'nanopb.proto',
                              result, 'nanopb')
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(
        description='Add nanopb-validate rules (and nanopb sizes) next to protovalidate (buf.validate) options.')
    parser.add_argument('source', help='a .proto file or a project folder of .proto files')
    parser.add_argument('--out', help='write the result into this folder; without it the project is '
                                      'changed in place (only additions)')
    parser.add_argument('--backup', action='store_true',
                        help='in place: keep each changed file as <file>.proto.bak first')
    parser.add_argument('--replace', action='store_true',
                        help='replace the buf.validate options and import instead of adding ours next to them '
                             '(needs --out; buf\'s validate.proto is then not copied)')
    parser.add_argument('--validate-name', default=DEFAULT_NAME, metavar='NAME',
                        help='file name of our rules file (default: %s), next to buf\'s validate.proto '
                             'or at the top of the project' % DEFAULT_NAME)
    parser.add_argument('--validate-import', default='validate.proto', metavar='PATH',
                        help='--replace only: what replaces import "buf/validate/validate.proto" '
                             '(default: validate.proto)')
    parser.add_argument('--no-sizes', action='store_true',
                        help='do not add (nanopb).max_size / max_count from the buf limits')
    parser.add_argument('--validate-proto', metavar='FILE', help='our validate.proto to copy (default: the one of '
                        'this checkout, %s)' % os.path.relpath(DEFAULT_VALIDATE_PROTO))
    parser.add_argument('--nanopb-proto', metavar='FILE', help='nanopb.proto to copy (default: the one of this '
                        'checkout, %s)' % os.path.relpath(DEFAULT_NANOPB_PROTO))
    parser.add_argument('--strict', action='store_true', help='exit 1 if any rule is not enforced by nanopb-validate')
    args = parser.parse_args(argv)

    if args.replace and (not args.out or os.path.abspath(args.out) == os.path.abspath(args.source)):
        parser.error('--replace needs --out, a folder other than the source: it removes the buf.validate options')
    if os.path.basename(args.validate_name) != args.validate_name or not args.validate_name.endswith('.proto') or \
            args.validate_name in ('validate.proto', 'nanopb.proto'):
        parser.error('--validate-name must be a file name ending in .proto, other than validate.proto and '
                     'nanopb.proto')
    opts = Options(append=not args.replace, validate_import=args.validate_import, validate_name=args.validate_name,
                   sizes=not args.no_sizes, validate_proto=args.validate_proto, nanopb_proto=args.nanopb_proto,
                   backup=args.backup)
    result = convert_path(args.source, args.out, opts=opts)

    where = 'in place' if result.in_place else 'into ' + args.out
    print('%d file(s) changed %s (%s)' % (len(result.converted), where,
                                          'replaced buf.validate' if args.replace else
                                          'buf.validate kept, (validate.rules) added'))
    if result.copied:
        print('copied unchanged: %d file(s)' % len(result.copied))
    for rel in result.written:
        print('added: %s' % rel)
    for rel in result.backups:
        print('backup: %s' % rel)
    if result.validate_imports:
        print('rules file imported as: %s' % ', '.join(sorted(result.validate_imports)))
    if result.nanopb_imports:
        print('nanopb.proto imported as: %s' % ', '.join(sorted(result.nanopb_imports)))
    for change in result.migrated:
        print('updated (earlier version\'s name of our rules file): %s' % change)
    for change in result.imports_added:
        print('missing import of buf\'s validate.proto added: %s' % change)
    for change in result.imports_removed:
        print('unused import removed: %s' % change)
    if result.sized:
        print('\nnanopb sizes added from the buf limits (static storage):')
        for rel, field, option, value in result.sized:
            print('  %-28s %-40s %s = %d' % (rel, field, option, value))
    if result.unsized:
        print('\nno limit in the buf rules to size these from (they stay pb_callback_t): give each one in '
              'the .options file next to its .proto, e.g. "pkg.Msg.name max_length:32":')
        for rel, field, option in result.unsized:
            print('  %-28s %-40s %s' % (rel, field, option))
    if result.report.items:
        print('\nnot enforced by nanopb-validate%s:' % ('' if args.replace else ' (the buf rules stay in the files)'))
        for where, rule, why in result.report.items:
            print('  %-28s %-34s %s' % (where, rule, why))
    if result.failed:
        print('\nNOT converted, left unchanged (please send this file and message):')
        for rel, why in result.failed:
            print('  %-28s %s' % (rel, why))
        return 1
    return 1 if (args.strict and result.report.items) else 0


if __name__ == '__main__':
    sys.exit(main())
