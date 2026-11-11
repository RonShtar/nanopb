"""Layout of generated C: C89-style blocks (declarations first), the final tidy pass, and the
#include format for runtime headers (nanopb's -L, e.g. <NanoPB/pb.h>).
"""

import re

_FOR_DECL_RE = re.compile(r'for \(((?:const )?(?:pb_size_t|size_t|unsigned|int|u?int\w*_t))\s+(\w+) = ')
_DECL_RE = re.compile(r'^(?:static\s+)?(?:const\s+)?(?:struct\s+)?[A-Za-z_]\w*(?:\s+const)?'
                      r'(?:\s*\*+\s*|\s+)[A-Za-z_]\w*\s*(?:\[[^\]]*\])*\s*(?:=|;)')
_NOT_DECL = ('return ', 'else ', 'goto ', 'case ', 'break;', 'continue;')


#: How generated files include the runtime headers (pb_validate.h, pb.h, ...):
#: nanopb's -L / --library-include-format, which the plugin copies here.
LIBRARY_INCLUDE_FORMAT = '#include <%s>'


#: The pb_validate.h version the generated code needs (PB_VALIDATE_RUNTIME_VERSION).
RUNTIME_VERSION = 2
RUNTIME_CHECK = ('#if !defined(PB_VALIDATE_RUNTIME_VERSION) || PB_VALIDATE_RUNTIME_VERSION < %d\n'
                 '#error "pb_validate.h is older than this generated code: use pb_validate.h and pb_validate.c '
                 'from the validate/runtime/ of the same nanopb checkout"\n'
                 '#endif\n' % RUNTIME_VERSION)


def lib_include(header: str) -> str:
    """An #include line for a runtime header, in nanopb's include format."""

    fmt = LIBRARY_INCLUDE_FORMAT
    return (fmt % header if '%s' in fmt else fmt) + '\n'


_PP_INDENT_RE = re.compile(r'^[ \t]+#', re.M)
_TRAILING_RE = re.compile(r'[ \t]+$', re.M)
_BLANK_RUN_RE = re.compile(r'\n{3,}')


def strip_comments(text: str) -> str:
    """Remove every comment except Doxygen blocks (/** ... */), outside string and char literals.

    A line that held only a comment disappears; code on the line stays.
    """

    out, i, n = [], 0, len(text)
    while i < n:
        c = text[i]
        if c in '"\'':
            j = i + 1
            while j < n and text[j] != c:
                j += 2 if text[j] == '\\' else 1
            out.append(text[i:j + 1])
            i = j + 1
        elif text.startswith('/*', i) or text.startswith('//', i):
            if text.startswith('//', i):
                end = text.find('\n', i)
                end = n if end < 0 else end
            else:
                end = text.find('*/', i + 2)
                end = n if end < 0 else end + 2
            if text.startswith('/**', i) and not text.startswith('/**/', i):
                out.append(text[i:end])
                i = end
                continue
            # A comment alone on its line(s) takes the line with it.
            line_start = ''.join(out).rfind('\n') + 1
            before = ''.join(out)[line_start:]
            rest_end = text.find('\n', end)
            rest = text[end:rest_end if rest_end >= 0 else n]
            if before.strip() == '' and rest.strip() == '':
                joined = ''.join(out)[:line_start]
                out = [joined]
                i = (rest_end + 1) if rest_end >= 0 else n
            else:
                i = end
        else:
            out.append(c)
            i += 1
    return '\n'.join(line.rstrip() for line in ''.join(out).split('\n'))


def tidy_c(text: str) -> str:
    """Final layout pass over generated C: preprocessor lines at column 0,
    no trailing whitespace, at most one blank line in a row."""

    text = _PP_INDENT_RE.sub('#', text)
    text = _TRAILING_RE.sub('', text)
    return _BLANK_RUN_RE.sub('\n\n', text)


def _is_declaration(line: str) -> bool:
    return bool(_DECL_RE.match(line)) and not line.startswith(_NOT_DECL)


def c_block(code: str, indent: int) -> str:
    """Lay out one generated C fragment at ``indent`` spaces, C89 style.

    Declarations always open a block: loop counters move out of the for
    header (``for (pb_size_t i = 0;`` becomes ``pb_size_t i;`` + ``for (i = 0;``)
    to the top of the fragment, a fragment that declares anything gets its
    own ``{ }``, and a declaration after a statement opens a nested block.
    Lines keep their relative indentation; preprocessor lines go to column 0.
    """

    if not code or not code.strip():
        return code
    hoisted = []

    def hoist(match):
        decl = '%s %s;' % (match.group(1), match.group(2))
        if decl not in hoisted:
            hoisted.append(decl)
        return 'for (%s = ' % match.group(2)

    code = _FOR_DECL_RE.sub(hoist, code)
    lines = [l.rstrip() for l in code.split('\n')]
    while lines and not lines[-1]:
        lines.pop()
    body = [l for l in lines if l.strip() and not l.lstrip().startswith('#')]
    base = min(len(l) - len(l.lstrip()) for l in body) if body else 0
    lines = [l if l.lstrip().startswith('#') else l[base:] for l in lines]

    wrap = bool(hoisted) or any(_is_declaration(l) for l in lines if l and not l[0].isspace())
    pad = ' ' * (indent + (4 if wrap else 0))
    out, opened, seen_statement = [], 0, False
    for decl in hoisted:
        out.append(pad + decl)
    for line in lines:
        if not line:
            out.append('')
            continue
        if line.lstrip().startswith('#'):
            out.append(line.lstrip())
            continue
        top = not line[0].isspace()
        if top and _is_declaration(line):
            if seen_statement:
                out.append(pad + '    ' * opened + '{')
                opened += 1
                seen_statement = False
        elif top:
            seen_statement = True
        out.append(pad + '    ' * opened + line)
    for level in range(opened - 1, -1, -1):
        out.append(pad + '    ' * level + '}')
    if wrap:
        out = [' ' * indent + '{'] + out + [' ' * indent + '}']
    return '\n'.join(out) + '\n'
