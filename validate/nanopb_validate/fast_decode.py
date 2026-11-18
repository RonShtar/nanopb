"""Generated buffer decoder for the protocol filter (the fast path).

pb_decode is a table-driven interpreter: for every packet it walks the field
descriptors, clears every field of the struct (whole string, bytes and Any.value
arrays included) and copies every Any.value into the struct, which is then decoded a
second time. This module writes, per message type, a straight-line decoder that
fills the same struct directly from the receive buffer:

  * a switch on the field number; varints, fixed values, strings and bytes are read
    inline, with nanopb's own acceptance rules (varint overflow, "integer too large"
    per field size, string/bytes/array overflow, packed arrays, missing required
    fields, zero tag, invalid wire types) so a packet is accepted or rejected exactly
    as pb_decode would;
  * only what the validators read is initialized (counts, has_ flags, which_ fields,
    scalars, the first byte of strings, the size of bytes), not whole arrays;
  * an Any inside the message is not copied: its type_url is (the validators read
    it), its value stays in the receive buffer and the Any's value array holds only
    where it is. After the whole message is decoded and validated, its Anys are
    resolved from the final struct exactly as on the pb_decode path (so a field
    seen twice, merged or replaced by another oneof member counts as pb_decode
    counts it), each payload read straight from the packet.

The validators are the same generated functions as before, run on the same struct,
so validation is identical. Whatever the decoder does not reproduce exactly returns
PBF_UNSURE and the existing pb_decode path decides: messages with proto2 default
values (also checked at run time on the descriptors), and builds with PB_VALIDATE_DEBUG,
PB_VALIDATE_UTF8, PB_CONVERT_DOUBLE_FLOAT, PB_WITHOUT_64BIT or PB_MESSAGE_NESTING_MAX.
Message types it cannot decode at all (callback/pointer fields, fixed_count arrays,
extensions, more than 64 required fields, an Any.value smaller than a pointer)
keep the pb_decode path only.

PB_VALIDATE_FILTER_NO_FAST_DECODE turns it off; PB_VALIDATE_FILTER_TEST_POISON fills
the struct with 0xA5 first (tests: any field the decoder forgot to initialize then
shows up as a different verdict than pb_decode's).
"""

KIND = {
    'BOOL': 'BOOL',
    'INT32': 'INT', 'INT64': 'INT', 'ENUM': 'INT',
    'UINT32': 'UINT', 'UINT64': 'UINT', 'UENUM': 'UINT',
    'SINT32': 'SINT', 'SINT64': 'SINT',
    'FIXED32': 'F32', 'SFIXED32': 'F32', 'FLOAT': 'F32',
    'FIXED64': 'F64', 'SFIXED64': 'F64', 'DOUBLE': 'F64',
    'STRING': 'STRING', 'BYTES': 'BYTES', 'FIXED_LENGTH_BYTES': 'FBYTES',
    'MESSAGE': 'MESSAGE',
}
WIRE = {'BOOL': 'PB_WT_VARINT', 'INT': 'PB_WT_VARINT', 'UINT': 'PB_WT_VARINT', 'SINT': 'PB_WT_VARINT',
        'F32': 'PB_WT_32BIT', 'F64': 'PB_WT_64BIT'}
PACKABLE = ('BOOL', 'INT', 'UINT', 'SINT', 'F32', 'F64')

HELPERS = r'''#ifndef PBF_HELPERS_DEFINED
#define PBF_HELPERS_DEFINED
/* Results of a fast decode. */
#define PBF_OK 0
#define PBF_DROP 1
#define PBF_UNSURE 2

#ifdef PB_VALIDATE_FILTER_TEST_POISON
#define PBF_POISON(ptr) memset((ptr), 0xA5, sizeof(*(ptr)))
#else
#define PBF_POISON(ptr) ((void)0)
#endif
#define PBF_NODEF(TYPE) (TYPE##_msg.default_value == NULL)

/* Unused helpers are fine: not every protocol needs every reader. */
#if defined(__GNUC__) || defined(__clang__)
#define PBF_INLINE static inline __attribute__((unused))
#else
#define PBF_INLINE static inline
#endif

typedef struct {
    const pb_byte_t *p;
    const pb_byte_t *end;
} pbf_in_t;

/* An Any's value is not copied: its value array holds where the bytes are. */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((unused))
#endif
static const pb_byte_t pbf_empty[1] = {0};

PBF_INLINE void pbf_set_value_at(pb_byte_t *slot, const pb_byte_t *at)
{
    memcpy(slot, &at, sizeof(at));
}

PBF_INLINE const pb_byte_t *pbf_value_at(const pb_byte_t *slot)
{
    const pb_byte_t *at;
    memcpy(&at, slot, sizeof(at));
    return at;
}

/* pb_decode_varint32(), same accepted encodings. */
PBF_INLINE bool pbf_varint32(pbf_in_t *in, uint32_t *dest)
{
    const pb_byte_t *p = in->p;
    uint32_t byte, result;
    uint_fast8_t bitpos = 7;

    if (p == in->end)
        return false;
    byte = *p++;
    if ((byte & 0x80) == 0) {
        in->p = p;
        *dest = byte;
        return true;
    }
    result = byte & 0x7F;
    do {
        if (p == in->end)
            return false;
        byte = *p++;
        if (bitpos >= 32) {
            uint32_t sign_extension = (bitpos < 63) ? 0xFF : 0x01;
            bool valid_extension = ((byte & 0x7F) == 0x00 || ((result >> 31) != 0 && byte == sign_extension));
            if (bitpos >= 64 || !valid_extension)
                return false;
        } else if (bitpos == 28) {
            if ((byte & 0x70) != 0 && (byte & 0x78) != 0x78)
                return false;
            result |= (uint32_t)(byte & 0x0F) << bitpos;
        } else {
            result |= (uint32_t)(byte & 0x7F) << bitpos;
        }
        bitpos = (uint_fast8_t)(bitpos + 7);
    } while (byte & 0x80);
    in->p = p;
    *dest = result;
    return true;
}

/* pb_decode_varint(), same accepted encodings. */
PBF_INLINE bool pbf_varint64(pbf_in_t *in, uint64_t *dest)
{
    const pb_byte_t *p = in->p;
    uint64_t result = 0;
    uint_fast8_t bitpos = 0;
    pb_byte_t byte;

    do {
        if (p == in->end)
            return false;
        byte = *p++;
        if (bitpos >= 63 && (byte & 0xFE) != 0)
            return false;
        result |= (uint64_t)(byte & 0x7F) << bitpos;
        bitpos = (uint_fast8_t)(bitpos + 7);
    } while (byte & 0x80);
    in->p = p;
    *dest = result;
    return true;
}

PBF_INLINE bool pbf_advance(pbf_in_t *in, size_t count)
{
    if ((size_t)(in->end - in->p) < count)
        return false;
    in->p += count;
    return true;
}

/* pb_skip_field() of an unknown field. */
PBF_INLINE bool pbf_skip(pbf_in_t *in, uint32_t wire_type)
{
    uint32_t size;
    switch (wire_type) {
        case PB_WT_VARINT:
            do {
                if (in->p == in->end)
                    return false;
            } while (*in->p++ & 0x80);
            return true;
        case PB_WT_64BIT:
            return pbf_advance(in, 8);
        case PB_WT_STRING:
            return pbf_varint32(in, &size) && pbf_advance(in, (size_t)size);
        case PB_WT_32BIT:
            return pbf_advance(in, 4);
        default:
            return false;
    }
}

/* pb_make_string_substream(): the next length-delimited value as its own reader. */
PBF_INLINE bool pbf_sub(pbf_in_t *in, pbf_in_t *sub)
{
    uint32_t size;
    if (!pbf_varint32(in, &size) || (size_t)(in->end - in->p) < (size_t)size)
        return false;
    sub->p = in->p;
    sub->end = in->p + size;
    in->p = sub->end;
    return true;
}

/* pb_dec_varint()'s store: the value must fit the field's size ("integer too large"). */
PBF_INLINE bool pbf_store_int(void *dest, size_t size, int64_t value)
{
    if (size == sizeof(int64_t)) {
        memcpy(dest, &value, sizeof(value));
        return true;
    } else if (size == sizeof(int32_t)) {
        int32_t v = (int32_t)value;
        memcpy(dest, &v, sizeof(v));
        return v == value;
    } else if (size == sizeof(int_least16_t)) {
        int_least16_t v = (int_least16_t)value;
        memcpy(dest, &v, sizeof(v));
        return v == value;
    } else if (size == sizeof(int_least8_t)) {
        int_least8_t v = (int_least8_t)value;
        memcpy(dest, &v, sizeof(v));
        return v == value;
    }
    return false;
}

PBF_INLINE bool pbf_store_uint(void *dest, size_t size, uint64_t value)
{
    if (size == sizeof(uint64_t)) {
        memcpy(dest, &value, sizeof(value));
        return true;
    } else if (size == sizeof(uint32_t)) {
        uint32_t v = (uint32_t)value;
        memcpy(dest, &v, sizeof(v));
        return v == value;
    } else if (size == sizeof(uint_least16_t)) {
        uint_least16_t v = (uint_least16_t)value;
        memcpy(dest, &v, sizeof(v));
        return v == value;
    } else if (size == sizeof(uint_least8_t)) {
        uint_least8_t v = (uint_least8_t)value;
        memcpy(dest, &v, sizeof(v));
        return v == value;
    }
    return false;
}

PBF_INLINE bool pbf_fixed32(pbf_in_t *in, void *dest)
{
    if ((size_t)(in->end - in->p) < 4)
        return false;
#if defined(PB_LITTLE_ENDIAN_8BIT) && PB_LITTLE_ENDIAN_8BIT == 1
    memcpy(dest, in->p, 4);
#else
    {
        uint32_t v = ((uint32_t)in->p[0]) | ((uint32_t)in->p[1] << 8) |
                     ((uint32_t)in->p[2] << 16) | ((uint32_t)in->p[3] << 24);
        memcpy(dest, &v, 4);
    }
#endif
    in->p += 4;
    return true;
}

PBF_INLINE bool pbf_fixed64(pbf_in_t *in, void *dest)
{
    if ((size_t)(in->end - in->p) < 8)
        return false;
#if defined(PB_LITTLE_ENDIAN_8BIT) && PB_LITTLE_ENDIAN_8BIT == 1
    memcpy(dest, in->p, 8);
#else
    {
        uint64_t v = ((uint64_t)in->p[0]) | ((uint64_t)in->p[1] << 8) |
                        ((uint64_t)in->p[2] << 16) | ((uint64_t)in->p[3] << 24) |
                        ((uint64_t)in->p[4] << 32) | ((uint64_t)in->p[5] << 40) |
                        ((uint64_t)in->p[6] << 48) | ((uint64_t)in->p[7] << 56);
        memcpy(dest, &v, 8);
    }
#endif
    in->p += 8;
    return true;
}

/* pb_dec_string(): into a char array of `capacity` bytes, NUL-terminated. */
PBF_INLINE bool pbf_string(pbf_in_t *in, char *dest, size_t capacity)
{
    uint32_t size;
    if (!pbf_varint32(in, &size) || size == (uint32_t)-1 || (size_t)(size + 1) > capacity ||
        (size_t)(in->end - in->p) < (size_t)size)
        return false;
    memcpy(dest, in->p, (size_t)size);
    dest[size] = '\0';
    in->p += size;
    return true;
}

/* pb_dec_bytes()'s checks; *at is where the bytes are in the packet. */
PBF_INLINE bool pbf_bytes_at(pbf_in_t *in, pb_size_t *size_out, size_t capacity, const pb_byte_t **at)
{
    uint32_t size;
    size_t alloc_size;
    if (!pbf_varint32(in, &size) || size > PB_SIZE_MAX)
        return false;
    alloc_size = PB_BYTES_ARRAY_T_ALLOCSIZE(size);
    if (size > alloc_size || alloc_size > capacity || (size_t)(in->end - in->p) < (size_t)size)
        return false;
    *size_out = (pb_size_t)size;
    *at = in->p;
    in->p += size;
    return true;
}

PBF_INLINE bool pbf_bytes(pbf_in_t *in, pb_size_t *size_out, pb_byte_t *dest, size_t capacity)
{
    const pb_byte_t *at;
    if (!pbf_bytes_at(in, size_out, capacity, &at))
        return false;
    memcpy(dest, at, (size_t)*size_out);
    return true;
}

/* pb_dec_fixed_length_bytes(). */
PBF_INLINE bool pbf_fixed_bytes(pbf_in_t *in, pb_byte_t *dest, size_t capacity)
{
    uint32_t size;
    if (!pbf_varint32(in, &size) || size > PB_SIZE_MAX)
        return false;
    if (size == 0) {
        memset(dest, 0, capacity);
        return true;
    }
    if ((size_t)size != capacity || (size_t)(in->end - in->p) < (size_t)size)
        return false;
    memcpy(dest, in->p, capacity);
    in->p += size;
    return true;
}

/* Field statements of the generated decoders: R is the reader, L the struct field. */
#define PBF_NEED(cond) do { if (!(cond)) return PBF_DROP; } while (0)
#define PBF_TRY(call) do { int pbf_r_ = (call); if (pbf_r_ != PBF_OK) return pbf_r_; } while (0)
#define PBF_WIRE(wire_type) PBF_NEED((key & 7u) == (uint32_t)(wire_type))
#define PBF_BOOL(R, L) do { uint32_t pbf_v_; PBF_NEED(pbf_varint32((R), &pbf_v_)); (L) = (pbf_v_ != 0); } while (0)
#define PBF_INT(R, L) do { uint64_t pbf_v_; PBF_NEED(pbf_varint64((R), &pbf_v_)); \
    PBF_NEED(pbf_store_int(&(L), sizeof(L), sizeof(L) == sizeof(int64_t) ? (int64_t)pbf_v_ \
                                                                           : (int64_t)(int32_t)pbf_v_)); } while (0)
#define PBF_UINT(R, L) do { uint64_t pbf_v_; PBF_NEED(pbf_varint64((R), &pbf_v_)); \
    PBF_NEED(pbf_store_uint(&(L), sizeof(L), pbf_v_)); } while (0)
#define PBF_SINT(R, L) do { uint64_t pbf_v_; PBF_NEED(pbf_varint64((R), &pbf_v_)); \
    PBF_NEED(pbf_store_int(&(L), sizeof(L), (pbf_v_ & 1) ? (int64_t)(~(pbf_v_ >> 1)) \
                                                         : (int64_t)(pbf_v_ >> 1))); } while (0)
#define PBF_F32(R, L) PBF_NEED(pbf_fixed32((R), &(L)))
#define PBF_F64(R, L) PBF_NEED(pbf_fixed64((R), &(L)))
#define PBF_STRING(R, L) PBF_NEED(pbf_string((R), (L), sizeof(L)))
#define PBF_BYTES(R, L) PBF_NEED(pbf_bytes((R), &(L).size, (L).bytes, sizeof(L)))
#define PBF_FBYTES(R, L) PBF_NEED(pbf_fixed_bytes((R), (L), sizeof(L)))
#define PBF_SUB(R, FUNC, L) do { pbf_in_t pbf_s_; PBF_NEED(pbf_sub((R), &pbf_s_)); \
    PBF_TRY(FUNC(pbf_s_.p, pbf_s_.end, &(L), depth)); } while (0)
#endif /* PBF_HELPERS_DEFINED */
'''


class FastDecodeEmitter(object):
    """C code of the fast path for one protocol filter (see the module docstring)."""

    def __init__(self, owner):
        self.o = owner                  # ProtocolFilterEmitter: ir(), ctype(), any_ir, holds_any()
        self.name = owner.name
        self.up = owner.name.upper()
        self._eligible = {}
        self.types = []                 # message IRs that get a decoder, dependencies first
        self._seen = set()

    # -- model ----------------------------------------------------------------

    def key(self, msg):
        ctype = str(self.o.ctype(msg))
        return ctype[len(self.name) + 1:] if ctype.startswith(self.name + '_') else ctype

    def is_any(self, field):
        return field.pbtype == 'MESSAGE' and self.o.ir(field.ctype) is self.o.any_ir

    def any_ok(self):
        fields = dict((f.tag, f) for f in self.o.any_ir.fields if f.pbtype != 'oneof')
        return (set(fields) == {1, 2} and fields[1].name == 'type_url' and fields[1].pbtype == 'STRING'
                and fields[2].name == 'value' and fields[2].pbtype == 'BYTES'
                and all(f.allocation == 'STATIC' for f in fields.values())
                and (fields[2].max_size or 0) >= 8)     # room for where the value is

    def eligible(self, msg, active=()):
        """Can every field of `msg` (sub-messages included, up to an Any) be decoded here?"""
        key = str(msg.name)
        if key in self._eligible:
            return self._eligible[key]
        if key in active:
            return False
        ok, required = True, 0
        for oneof, field in self.o.plain_fields(msg):
            if (field.allocation != 'STATIC' or field.rules == 'FIXARRAY' or field.pbtype not in KIND
                    or getattr(field, 'default', None) is not None):
                ok = False
                break
            if field.rules == 'REQUIRED':
                required += 1
            if field.pbtype != 'MESSAGE':
                continue
            sub = self.o.ir(field.ctype)
            if sub is None:
                ok = False
            elif sub is self.o.any_ir:
                ok = self.any_ok()
            else:
                ok = self.eligible(sub, active + (key,))
            if not ok:
                break
        if required > 64:
            ok = False
        self._eligible[key] = ok
        return ok

    def collect(self, msg):
        """`msg` and the sub-message types it decodes, dependencies first."""
        key = str(msg.name)
        if key in self._seen:
            return
        self._seen.add(key)
        for _, field in self.o.plain_fields(msg):
            if field.pbtype == 'MESSAGE' and not self.is_any(field):
                self.collect(self.o.ir(field.ctype))
        self.types.append(msg)

    def reachable(self, msg, out=None):
        out = [] if out is None else out
        if str(msg.name) in [str(m.name) for m in out]:
            return out
        out.append(msg)
        for _, field in self.o.plain_fields(msg):
            if field.pbtype == 'MESSAGE' and not self.is_any(field):
                self.reachable(self.o.ir(field.ctype), out)
        return out

    # -- emission -------------------------------------------------------------

    def lvalue(self, oneof, field):
        if oneof is None:
            return 'm->%s' % field.name
        if oneof.anonymous:
            return 'm->%s' % field.name
        return 'm->%s.%s' % (oneof.name, field.name)

    def init_value(self, target, field):
        kind = KIND[field.pbtype]
        if kind == 'STRING':
            return ["%s[0] = '\\0';" % target]
        if kind == 'BYTES':
            return ['%s.size = 0;' % target]
        if kind == 'FBYTES':
            return ['memset(%s, 0, sizeof(%s));' % (target, target)]
        if kind == 'MESSAGE':
            if self.is_any(field):
                return ["%s.type_url[0] = '\\0';" % target, '%s.value.size = 0;' % target,
                        'pbf_set_value_at(%s.value.bytes, pbf_empty);' % target]
            return ['%s_finit_%s(&%s);' % (self.name, self.key(self.o.ir(field.ctype)), target)]
        return ['%s = 0;' % target]

    def value_stmt(self, reader, target, field):
        kind = KIND[field.pbtype]
        if kind == 'MESSAGE':
            if self.is_any(field):
                return 'PBF_SUB(%s, %s_fany, %s);' % (reader, self.name, target)
            return 'PBF_SUB(%s, %s_fdec_%s, %s);' % (reader, self.name, self.key(self.o.ir(field.ctype)), target)
        return 'PBF_%s(%s, %s);' % (kind, reader, target)

    def finit(self, msg):
        ctype = self.o.ctype(msg)
        lines = ['static void %s_finit_%s(%s *m)' % (self.name, self.key(msg), ctype), '{']
        body = []
        for field in msg.fields:
            if field.pbtype == 'oneof':
                body.append('m->which_%s = 0;' % field.name)
            elif field.rules == 'REPEATED':
                body.append('m->%s_count = 0;' % field.name)
            else:
                if field.rules == 'OPTIONAL':
                    body.append('m->has_%s = false;' % field.name)
                body += self.init_value('m->%s' % field.name, field)
        lines += ['    ' + line for line in (body or ['(void)m;'])]
        lines.append('}')
        return lines

    def field_case(self, msg, oneof, field, required_bit):
        ctype = self.o.ctype(msg)
        target = self.lvalue(oneof, field)
        kind = KIND[field.pbtype]
        wire = WIRE.get(kind, 'PB_WT_STRING')
        out = ['case %d: /* %s */' % (field.tag, field.name)]
        body = []
        if field.rules == 'REPEATED':
            count = 'm->%s_count' % field.name
            room = '%s < pb_arraysize(%s, %s)' % (count, ctype, field.name)
            item = '%s[%s]' % (target, count)
            single = ['PBF_NEED(%s);' % room, 'PBF_WIRE(%s);' % wire]
            if kind == 'MESSAGE':
                single += self.init_value(item, field)
            single += [self.value_stmt('&in', item, field), '%s++;' % count]
            if kind in PACKABLE:
                body += ['if ((key & 7u) == PB_WT_STRING) {',
                         '    pbf_in_t s;',
                         '    PBF_NEED(pbf_sub(&in, &s));',
                         '    while (s.p != s.end && %s) {' % room,
                         '        ' + self.value_stmt('&s', item, field),
                         '        %s++;' % count,
                         '    }',
                         '    PBF_NEED(s.p == s.end);',
                         '} else {']
                body += ['    ' + line for line in single]
                body.append('}')
            else:
                body += single
        else:
            body.append('PBF_WIRE(%s);' % wire)
            if oneof is not None:
                tag = '%s_%s_tag' % (msg.name, field.name)
                which = 'm->which_%s' % oneof.name
                if kind == 'MESSAGE':
                    body.append('if (%s != %s) {' % (which, tag))
                    body += ['    ' + line for line in self.init_value(target, field)]
                    body.append('    %s = %s;' % (which, tag))
                    body.append('}')
                else:
                    body.append('%s = %s;' % (which, tag))
            elif field.rules == 'OPTIONAL':
                body.append('m->has_%s = true;' % field.name)
            body.append(self.value_stmt('&in', target, field))
            if required_bit is not None:
                body.append('pbf_req%d |= 0x%08xu;' % (required_bit >> 5, 1 << (required_bit & 31)))
        body.append('break;')
        return out + ['    ' + line for line in body]

    def fdec(self, msg):
        ctype = self.o.ctype(msg)
        required = [f for o, f in self.o.plain_fields(msg) if o is None and f.rules == 'REQUIRED']
        words = (len(required) + 31) // 32
        lines = ['static int %s_fdec_%s(const pb_byte_t *p, const pb_byte_t *end, %s *m, int depth)'
                 % (self.name, self.key(msg), ctype), '{',
                 '    pbf_in_t in;',
                 '    uint32_t key;']
        for w in range(words):
            lines.append('    uint32_t pbf_req%d = 0;' % w)
        lines += ['    (void)depth;', '    in.p = p;', '    in.end = end;',
                  '    while (in.p != in.end) {',
                  '        PBF_NEED(pbf_varint32(&in, &key));',
                  '        switch (key >> 3) {',
                  '            case 0:',
                  '                return PBF_DROP; /* zero tag */']
        bit = 0
        for oneof, field in self.o.plain_fields(msg):
            rbit = None
            if oneof is None and field.rules == 'REQUIRED':
                rbit, bit = bit, bit + 1
            lines += ['            ' + line for line in self.field_case(msg, oneof, field, rbit)]
        lines += ['            default:',
                  '                PBF_NEED(pbf_skip(&in, key & 7u));',
                  '                break;',
                  '        }',
                  '    }']
        for w in range(words):
            n = min(32, len(required) - 32 * w)
            lines.append('    PBF_NEED(pbf_req%d == 0x%08xu); /* missing required field */'
                         % (w, (1 << n) - 1))
        lines += ['    return PBF_OK;', '}']
        return lines

    def fany(self):
        any_ctype = self.o.ctype(self.o.any_ir)
        n = self.name
        return [
            '/* An Any field: type_url into the struct; for the value only its size and where it is. */',
            'static int %s_fany(const pb_byte_t *p, const pb_byte_t *end, %s *m, int depth)' % (n, any_ctype),
            '{',
            '    pbf_in_t in;',
            '    uint32_t key;',
            '    const pb_byte_t *value;',
            '    (void)depth;',
            '    in.p = p;',
            '    in.end = end;',
            '    while (in.p != in.end) {',
            '        PBF_NEED(pbf_varint32(&in, &key));',
            '        switch (key >> 3) {',
            '            case 0:',
            '                return PBF_DROP; /* zero tag */',
            '            case 1: /* type_url */',
            '                PBF_WIRE(PB_WT_STRING);',
            '                PBF_STRING(&in, m->type_url);',
            '                break;',
            '            case 2: /* value: not copied */',
            '                PBF_WIRE(PB_WT_STRING);',
            '                PBF_NEED(pbf_bytes_at(&in, &m->value.size, sizeof(m->value), &value));',
            '                pbf_set_value_at(m->value.bytes, value);',
            '                break;',
            '            default:',
            '                PBF_NEED(pbf_skip(&in, key & 7u));',
            '                break;',
            '        }',
            '    }',
            '    return PBF_OK;',
            '}',
        ]

    def source(self, protocol_irs):
        """The fast-path block, or nothing when no protocol message qualifies."""
        tops = [(fqn, msg) for fqn, msg in protocol_irs if self.eligible(msg)]
        if not tops:
            return []
        for _, msg in tops:
            self.collect(msg)
        uses_any = any(self.is_any(f) for m in self.types for _, f in self.o.plain_fields(m))
        up = self.up
        out = ['/* Fast path: each message decoded straight from the packet into its struct (see',
               ' * nanopb_validate/fast_decode.py); anything it does not reproduce exactly goes to',
               ' * pb_decode below. PB_VALIDATE_FILTER_NO_FAST_DECODE turns it off. */',
               '#if !defined(PB_VALIDATE_DEBUG) && !defined(PB_VALIDATE_UTF8) && !defined(PB_CONVERT_DOUBLE_FLOAT) && \\',
               '    !defined(PB_WITHOUT_64BIT) && !defined(PB_MESSAGE_NESTING_MAX) && \\',
               '    !defined(PB_VALIDATE_FILTER_NO_FAST_DECODE)',
               '#define %s_FAST_DECODE 1' % up,
               '#endif', '', '#ifdef %s_FAST_DECODE' % up]
        out += HELPERS.rstrip('\n').split('\n')
        out.append('')
        for msg in self.types:
            ctype = self.o.ctype(msg)
            out.append('static void %s_finit_%s(%s *m);' % (self.name, self.key(msg), ctype))
            out.append('static int %s_fdec_%s(const pb_byte_t *p, const pb_byte_t *end, %s *m, int depth);'
                       % (self.name, self.key(msg), ctype))
        if uses_any:
            out.append('static int %s_fany(const pb_byte_t *p, const pb_byte_t *end, %s *m, int depth);'
                       % (self.name, self.o.ctype(self.o.any_ir)))
        out.append('')
        if uses_any:
            out += self.fany() + ['']
        for msg in self.types:
            out += ['/* %s */' % msg.name] + self.finit(msg) + [''] + self.fdec(msg) + ['']
        for _, msg in tops:
            ctype = self.o.ctype(msg)
            types = ' && '.join('PBF_NODEF(%s)' % self.o.ctype(m) for m in self.reachable(msg))
            out += ['/* Fast path of %s; PBF_UNSURE when a type it fills has proto2 default values. */' % msg.name,
                    'static int %s(const pb_byte_t *value, size_t value_size, %s *m, int depth)'
                    % (self.entry(msg), ctype),
                    '{',
                    '    if (!(%s))' % types,
                    '        return PBF_UNSURE;',
                    '    PBF_POISON(m);',
                    '    %s_finit_%s(m);' % (self.name, self.key(msg)),
                    '    return %s_fdec_%s(value, value + value_size, m, depth);' % (self.name, self.key(msg)),
                    '}', '']
        out.append('#endif /* %s_FAST_DECODE */' % up)
        out.append('')
        return [line + '\n' for line in out]

    def entry(self, msg):
        return '%s_fast_%s' % (self.name, self.key(msg))

    def fast_macro(self, drop):
        """<UNIT>_FAST(FAST_FUNC, NAME, VALIDATE): the start of a check function."""
        up = self.up
        body = [
            'do {',
            '    {',
            '        int pbf_r = FAST_FUNC(value, value_size, payload, depth);',
            '        if (pbf_r == PBF_OK) {',
            '            if (!VALIDATE(payload, NULL)) {',
            '                %sNAME " validation failed");' % drop,
            '                return -1;',
            '            }',
            '            return 0;',
            '        }',
            '        if (pbf_r == PBF_DROP) {',
            '            %s"cannot decode " NAME);' % drop,
            '            return -1;',
            '        }',
            '    }',
            '} while (0)',
        ]
        width = max(len(line) for line in body) + 5
        text = ('/* Try the fast path; PBF_UNSURE falls through to pb_decode. */\n'
                '#ifdef %s_FAST_DECODE\n#define %s_FAST(FAST_FUNC, NAME, VALIDATE) \\\n' % (up, up))
        for i, line in enumerate(body):
            text += '    ' + (line if i == len(body) - 1 else line.ljust(width) + '\\') + '\n'
        text += '#else\n#define %s_FAST(FAST_FUNC, NAME, VALIDATE) do { } while (0)\n#endif\n\n' % up
        return text
