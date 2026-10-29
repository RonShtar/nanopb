-- nanopb_any_dissector.lua
--
-- Recursive protobuf dissector for Wireshark that follows google.protobuf.Any
-- by its type_url. Message definitions come from nanopb/schema.luadata next to
-- this file, written by tools/wireshark/backend/nanopb_wireshark.py
-- (install-dissector, or Tools > nanopb > Install / update dissector).
--
-- Root message selection, in order:
--   1. the port map  (Preferences > Protocols > NANOPB > Port map, or
--      nanopb/ports.luadata written by install-dissector)
--   2. "Default message" preference (used e.g. with Decode As)
--   3. google.protobuf.Any, if "Treat unknown payload as Any" is enabled
--   4. a raw field/wire-type tree
--
-- Works with Wireshark 3.6+ (Lua 5.2 - 5.4).

local PLUGIN_VERSION = "1.0.0"

if set_plugin_info then
    set_plugin_info({
        version = PLUGIN_VERSION,
        description = "Recursive protobuf dissector with google.protobuf.Any support (nanopb)",
        repository = "https://github.com/nanopb/nanopb",
    })
end

-- ---------------------------------------------------------------------------
-- Schema
-- ---------------------------------------------------------------------------

local function script_dir()
    local src = debug.getinfo(1, "S").source
    if src:sub(1, 1) == "@" then src = src:sub(2) end
    return src:match("^(.*)[/\\]") or "."
end

local SEP = package.config:sub(1, 1)
local DATA_DIR = script_dir() .. SEP .. "nanopb"

-- Wireshark's loadfile raises an error for missing files instead of
-- returning nil, so check first and guard the call.
local function load_data(path)
    local f = io.open(path, "r")
    if not f then return nil end
    f:close()
    local loaded, chunk = pcall(loadfile, path)
    if not loaded or not chunk then return nil end
    local ok, value = pcall(chunk)
    if ok and type(value) == "table" then return value end
    return nil
end

local schema_path = os.getenv("NANOPB_WS_SCHEMA") or (DATA_DIR .. SEP .. "schema.luadata")
local schema = load_data(schema_path)
local schema_ok = schema ~= nil
schema = schema or { messages = {}, enums = {} }
local default_ports = load_data(os.getenv("NANOPB_WS_PORTS") or (DATA_DIR .. SEP .. "ports.luadata")) or {}

local ANY = "google.protobuf.Any"

-- FieldDescriptorProto.Type
local T = {
    DOUBLE = 1, FLOAT = 2, INT64 = 3, UINT64 = 4, INT32 = 5, FIXED64 = 6, FIXED32 = 7,
    BOOL = 8, STRING = 9, GROUP = 10, MESSAGE = 11, BYTES = 12, UINT32 = 13, ENUM = 14,
    SFIXED32 = 15, SFIXED64 = 16, SINT32 = 17, SINT64 = 18,
}
local LABEL_REPEATED = 3

local VARINT_TYPES = {
    [T.INT64] = true, [T.UINT64] = true, [T.INT32] = true, [T.BOOL] = true,
    [T.UINT32] = true, [T.ENUM] = true, [T.SINT32] = true, [T.SINT64] = true,
}
local FIXED32_TYPES = { [T.FLOAT] = true, [T.FIXED32] = true, [T.SFIXED32] = true }
local FIXED64_TYPES = { [T.DOUBLE] = true, [T.FIXED64] = true, [T.SFIXED64] = true }

-- ---------------------------------------------------------------------------
-- Protocol, fields, expert info
-- ---------------------------------------------------------------------------

local nanopb = Proto("nanopb", "nanopb Protobuf (recursive Any)")

local f_message  = ProtoField.string("nanopb.message", "Message type")
local f_field    = ProtoField.string("nanopb.field", "Field")
local f_type_url = ProtoField.string("nanopb.type_url", "Any type_url")
local f_unknown  = ProtoField.bytes("nanopb.unknown", "Unknown field")

-- Validation verdict, as pb_validate / the generated packet filters would decide.
local f_validation = ProtoField.string("nanopb.validation", "Validation")
local f_v_rule     = ProtoField.string("nanopb.validation.rule", "Violated rule")
local f_v_field    = ProtoField.string("nanopb.validation.field", "Field")
local f_v_detail   = ProtoField.string("nanopb.validation.detail", "Detail")
local f_v_unchecked = ProtoField.string("nanopb.validation.unchecked", "Not checked")

local fields = { f_message, f_field, f_type_url, f_unknown,
                 f_validation, f_v_rule, f_v_field, f_v_detail, f_v_unchecked }

local e_malformed = ProtoExpert.new("nanopb.malformed", "Malformed protobuf data",
    expert.group.MALFORMED, expert.severity.ERROR)
local e_unknown_type = ProtoExpert.new("nanopb.any.unknown_type", "Any type not in schema",
    expert.group.UNDECODED, expert.severity.WARN)
local e_no_schema = ProtoExpert.new("nanopb.no_schema",
    "nanopb schema not found; run Tools > nanopb > Install / update dissector",
    expert.group.UNDECODED, expert.severity.NOTE)
local e_depth = ProtoExpert.new("nanopb.depth", "Maximum nesting depth reached",
    expert.group.UNDECODED, expert.severity.WARN)
local e_violation = ProtoExpert.new("nanopb.validation.violation", "Validation rule violated",
    expert.group.PROTOCOL, expert.severity.WARN)
local e_decode = ProtoExpert.new("nanopb.validation.decode", "nanopb would fail to decode this message",
    expert.group.MALFORMED, expert.severity.WARN)
nanopb.experts = { e_malformed, e_unknown_type, e_no_schema, e_depth, e_violation, e_decode }

-- One typed ProtoField per schema field, so display filters such as
-- nanopb.demo.payloads.Ping.id == 5 work.
local function enum_valstring(type_name)
    local values = schema.enums[type_name]
    if not values then return nil end
    local copy = {}
    for k, v in pairs(values) do copy[k] = v end
    return copy
end

local typed_fields = {}  -- [msg_name][number] = ProtoField
for msg_name, msg in pairs(schema.messages) do
    typed_fields[msg_name] = {}
    for number, fd in pairs(msg.fields) do
        local abbr = "nanopb." .. msg_name .. "." .. fd.name
        local label = fd.name
        local t = fd.type
        local pf
        if t == T.INT32 or t == T.SINT32 or t == T.SFIXED32 then
            pf = ProtoField.int32(abbr, label, base.DEC)
        elseif t == T.ENUM then
            pf = ProtoField.int32(abbr, label, base.DEC, enum_valstring(fd.type_name))
        elseif t == T.UINT32 or t == T.FIXED32 then
            pf = ProtoField.uint32(abbr, label, base.DEC)
        elseif t == T.INT64 or t == T.SINT64 or t == T.SFIXED64 then
            pf = ProtoField.int64(abbr, label, base.DEC)
        elseif t == T.UINT64 or t == T.FIXED64 then
            pf = ProtoField.uint64(abbr, label, base.DEC)
        elseif t == T.FLOAT then
            pf = ProtoField.float(abbr, label)
        elseif t == T.DOUBLE then
            pf = ProtoField.double(abbr, label)
        elseif t == T.BOOL then
            pf = ProtoField.bool(abbr, label)
        elseif t == T.STRING then
            pf = ProtoField.string(abbr, label)
        elseif t == T.BYTES then
            pf = ProtoField.bytes(abbr, label)
        end
        if pf then
            typed_fields[msg_name][number] = pf
            fields[#fields + 1] = pf
        end
    end
end
nanopb.fields = fields

-- ---------------------------------------------------------------------------
-- Preferences and port registration
-- ---------------------------------------------------------------------------

local function default_port_map_string()
    local parts = {}
    for _, e in ipairs(default_ports) do
        if e.message then  -- protocol entries are registered with their Decode As protocol
            parts[#parts + 1] = string.format("%s:%d=%s", e.transport, e.port, e.message)
        end
    end
    return table.concat(parts, ",")
end

nanopb.prefs.port_map = Pref.string("Port map", default_port_map_string(),
    "Comma-separated transport:port=message entries, e.g. udp:5000=pkg.Envelope,tcp:7000=pkg.Cmd")
nanopb.prefs.default_message = Pref.string("Default message", "",
    "Root message for payloads without a port map entry (e.g. with Decode As). Empty = none")
nanopb.prefs.any_fallback = Pref.bool("Treat unknown payload as Any", true,
    "Decode payloads without a root message as google.protobuf.Any")
nanopb.prefs.heuristic = Pref.bool("Detect Any on any port (heuristic)", true,
    "Decode UDP/TCP payloads on unmapped ports that are a google.protobuf.Any of a known type")
nanopb.prefs.max_depth = Pref.uint("Maximum nesting depth", 32, "Guard against runaway recursion")
nanopb.prefs.validate = Pref.bool("Check validation rules", true,
    "Evaluate the validate.proto rules and show PASSED / DROPPED, like the generated nanopb filters")
nanopb.prefs.validate_any = Pref.bool("Validate Any payloads", true,
    "Also decode and validate the message inside google.protobuf.Any fields")

-- Protocols: one per folder of the protos root that uses google.protobuf.Any
-- (schema.protocols). Filled in below, once dissect() exists.
local protocols = {}
local protocol_names = {}
for name in pairs(schema.protocols or {}) do protocol_names[#protocol_names + 1] = name end
table.sort(protocol_names)
local protocol_choices = { { "none", "(none: decode by port map / Any)", 0 } }
for i, name in ipairs(protocol_names) do protocol_choices[#protocol_choices + 1] = { name, name, i } end
nanopb.prefs.protocol = Pref.enum("Protocol", 0,
    "Primary protocol: every NANOPB packet without a port map message is a google.protobuf.Any "
        .. "whose type_url selects a message of this protocol, validated like <protocol>_filter_udp",
    protocol_choices, false)

local function primary_protocol()
    local name = protocol_names[nanopb.prefs.protocol or 0]
    return name and protocols[name]
end

local port_map = { udp = {}, tcp = {} }
local registered = { udp = {}, tcp = {} }

local function parse_port_map(text)
    local map = { udp = {}, tcp = {} }
    for item in string.gmatch(text or "", "[^,;%s]+") do
        local transport, port, msg = item:match("^(%a+):(%d+)=([%w_%.]+)$")
        if transport then
            transport = transport:lower()
            if map[transport] then map[transport][tonumber(port)] = msg end
        end
    end
    return map
end

local function apply_ports()
    for transport, ports in pairs(registered) do
        local tbl = DissectorTable.get(transport .. ".port")
        for port in pairs(ports) do tbl:remove(port, nanopb) end
        registered[transport] = {}
    end
    port_map = parse_port_map(nanopb.prefs.port_map)
    for transport, ports in pairs(port_map) do
        local tbl = DissectorTable.get(transport .. ".port")
        for port in pairs(ports) do
            tbl:add(port, nanopb)
            registered[transport][port] = true
        end
    end
end

function nanopb.prefs_changed()
    apply_ports()
end

-- ---------------------------------------------------------------------------
-- Wire format decoding
-- ---------------------------------------------------------------------------

-- Returns UInt64 value and byte length, or nil if truncated / too long.
local function read_varint(tvb, offset, limit)
    local value = UInt64(0)
    local shift = 0
    local pos = offset
    while pos < limit and shift < 70 do
        local b = tvb(pos, 1):uint()
        value = value:bor(UInt64(b % 128):lshift(shift))
        pos = pos + 1
        if b < 128 then return value, pos - offset end
        shift = shift + 7
    end
    return nil
end

local function to_int64(u)
    return Int64.fromhex(u:tohex())
end

local function zigzag(u)
    local half = to_int64(u:rshift(1))
    if u:band(UInt64(1)) == UInt64(0) then return half end
    return -half - 1
end

-- Value of a varint-encoded scalar for display / typed fields.
local function varint_value(fd, u)
    local t = fd.type
    if t == T.UINT64 then return u end
    if t == T.INT64 then return to_int64(u) end
    if t == T.SINT64 then return zigzag(u) end
    if t == T.SINT32 then return zigzag(u):tonumber() end
    if t == T.INT32 or t == T.ENUM then return to_int64(u):tonumber() end
    if t == T.UINT32 then return u:band(UInt64(0xFFFFFFFF)):tonumber() end
    if t == T.BOOL then return u ~= UInt64(0) end
    return u
end

local decode_message  -- forward

-- True if the range is a structurally valid sequence of protobuf fields.
local function wire_ok(tvb, offset, length)
    local limit = offset + length
    local pos = offset
    while pos < limit do
        local key, klen = read_varint(tvb, pos, limit)
        if not key then return false end
        pos = pos + klen
        if key:rshift(3) == UInt64(0) then return false end
        local wire = key:band(UInt64(7)):tonumber()
        if wire == 0 then
            local _, vlen = read_varint(tvb, pos, limit)
            if not vlen then return false end
            pos = pos + vlen
        elseif wire == 1 then
            pos = pos + 8
        elseif wire == 5 then
            pos = pos + 4
        elseif wire == 2 then
            local len, llen = read_varint(tvb, pos, limit)
            if not len then return false end
            pos = pos + llen + len:tonumber()
        else
            return false
        end
        if pos > limit then return false end
    end
    return true
end

local function message_label(fd, number, type_name)
    return string.format("%s (%d): %s", fd.name, number, type_name)
end

local function add_scalar(tree, msg_name, number, fd, range, value, text)
    local pf = typed_fields[msg_name] and typed_fields[msg_name][number]
    local item
    if pf and value == nil then
        item = tree:add(pf, range)
    elseif pf then
        item = tree:add(pf, range, value)
    else
        item = tree:add(f_field, range, text)
    end
    item:append_text(string.format(" [#%d]", number))
    return item
end

local function enum_text(fd, n)
    local values = schema.enums[fd.type_name]
    local name = values and values[n]
    return name and string.format("%s (%d)", name, n) or tostring(n)
end

-- Decode one packed or non-packed scalar element starting at pos.
-- Returns bytes consumed or nil on error.
local function decode_scalar(tvb, pos, limit, wire, fd, tree, msg_name, number)
    local t = fd.type
    if wire == 0 then
        local u, len = read_varint(tvb, pos, limit)
        if not u then return nil end
        local value = varint_value(fd, u)
        local text = (t == T.ENUM) and enum_text(fd, value) or tostring(value)
        add_scalar(tree, msg_name, number, fd, tvb(pos, len), value,
            string.format("%s: %s", fd.name, text))
        return len
    elseif wire == 5 then
        if pos + 4 > limit then return nil end
        local r = tvb(pos, 4)
        local value
        if t == T.FLOAT then value = r:le_float()
        elseif t == T.SFIXED32 then value = r:le_int()
        else value = r:le_uint() end
        add_scalar(tree, msg_name, number, fd, r, value, string.format("%s: %s", fd.name, tostring(value)))
        return 4
    elseif wire == 1 then
        if pos + 8 > limit then return nil end
        local r = tvb(pos, 8)
        local value
        if t == T.DOUBLE then value = r:le_float()  -- le_float reads 4- and 8-byte ranges
        elseif t == T.SFIXED64 then value = r:le_int64()
        else value = r:le_uint64() end
        add_scalar(tree, msg_name, number, fd, r, value, string.format("%s: %s", fd.name, tostring(value)))
        return 8
    end
    return nil
end

-- Parse a google.protobuf.Any: returns type_url, type_name, value offset and
-- length (value may be nil), or nil if the range is not shaped like an Any.
local function parse_any(tvb, offset, length)
    local limit = offset + length
    local pos = offset
    local type_url, value_off, value_len
    while pos < limit do
        local key, klen = read_varint(tvb, pos, limit)
        if not key then return nil end
        pos = pos + klen
        local number = key:rshift(3):tonumber()
        local wire = key:band(UInt64(7)):tonumber()
        if wire ~= 2 or (number ~= 1 and number ~= 2) then return nil end
        local len, llen = read_varint(tvb, pos, limit)
        if not len then return nil end
        pos = pos + llen
        len = len:tonumber()
        if pos + len > limit then return nil end
        if number == 1 then
            type_url = len > 0 and tvb(pos, len):string(ENC_UTF_8) or ""
        else
            value_off, value_len = pos, len
        end
        pos = pos + len
    end
    if not type_url or type_url == "" then return nil end
    return type_url, (type_url:match("([^/]+)$") or type_url), value_off, value_len
end

local function decode_any(tvb, offset, length, tree, depth, pinfo)
    local type_url, type_name, value_off, value_len = parse_any(tvb, offset, length)
    if not type_url then return false end
    tree:add(f_type_url, tvb(offset, length), type_url)
    tree:append_text(" -> " .. type_name)
    if not value_off then return true end
    if schema.messages[type_name] then
        local sub = tree:add(f_message, tvb(value_off, value_len), type_name)
        sub:set_text(string.format("value: Any -> %s", type_name))
        decode_message(tvb, value_off, value_len, type_name, sub, depth + 1, pinfo)
    else
        local item = tree:add(f_unknown, tvb(value_off, value_len))
        item:set_text(string.format("value: %d bytes (type %s not in schema)", value_len, type_name))
        item:add_proto_expert_info(e_unknown_type, "Any type not in schema: " .. type_name)
    end
    return true
end

-- Decode `length` bytes at `offset` as message `msg_name` (nil = raw).
-- Returns true if the whole range parsed.
decode_message = function(tvb, offset, length, msg_name, tree, depth, pinfo)
    if depth > nanopb.prefs.max_depth then
        tree:add_proto_expert_info(e_depth)
        return false
    end
    if msg_name == ANY and decode_any(tvb, offset, length, tree, depth, pinfo) then
        return true
    end

    local msg = msg_name and schema.messages[msg_name]
    local limit = offset + length
    local pos = offset
    while pos < limit do
        local start = pos
        local key, klen = read_varint(tvb, pos, limit)
        if not key then
            tree:add_proto_expert_info(e_malformed, "Truncated field key")
            return false
        end
        pos = pos + klen
        local number = key:rshift(3):tonumber()
        local wire = key:band(UInt64(7)):tonumber()
        local fd = msg and msg.fields[number]
        if number == 0 then
            tree:add_proto_expert_info(e_malformed, "Field number 0")
            return false
        end

        if wire == 2 then
            local len, llen = read_varint(tvb, pos, limit)
            if not len or pos + llen + len:tonumber() > limit then
                tree:add_proto_expert_info(e_malformed, "Length exceeds message")
                return false
            end
            pos = pos + llen
            len = len:tonumber()
            local whole = tvb(start, pos - start + len)
            if fd and fd.type == T.MESSAGE then
                local sub = tree:add(f_message, whole, fd.type_name)
                sub:set_text(message_label(fd, number, fd.type_name))
                decode_message(tvb, pos, len, fd.type_name, sub, depth + 1, pinfo)
            elseif fd and fd.type == T.STRING then
                local value = len > 0 and tvb(pos, len):string(ENC_UTF_8) or ""
                add_scalar(tree, msg_name, number, fd, whole, value,
                    string.format("%s: %s", fd.name, value))
            elseif fd and fd.type == T.BYTES then
                -- Bytes fields take their value from the range (older
                -- Wireshark rejects a ByteArray value argument).
                if len > 0 then
                    local r = tvb(pos, len)
                    add_scalar(tree, msg_name, number, fd, r, nil,
                        string.format("%s: %s", fd.name, tostring(r:bytes())))
                else
                    tree:add(f_field, whole, fd.name):set_text(string.format("%s: <empty> [#%d]", fd.name, number))
                end
            elseif fd and fd.label == LABEL_REPEATED and
                    (VARINT_TYPES[fd.type] or FIXED32_TYPES[fd.type] or FIXED64_TYPES[fd.type]) then
                local sub = tree:add(f_field, whole, fd.name)
                sub:set_text(string.format("%s (%d): packed", fd.name, number))
                local elem_wire = VARINT_TYPES[fd.type] and 0 or (FIXED32_TYPES[fd.type] and 5 or 1)
                local p, n = pos, 0
                while p < pos + len do
                    local used = decode_scalar(tvb, p, pos + len, elem_wire, fd, sub, msg_name, number)
                    if not used then
                        sub:add_proto_expert_info(e_malformed, "Bad packed element")
                        break
                    end
                    p, n = p + used, n + 1
                end
                sub:append_text(string.format(" [%d]", n))
            else
                local item = tree:add(f_unknown, whole)
                item:set_text(string.format("field %d: %d bytes", number, len))
                -- Unknown length-delimited data may be a nested message.
                if len > 0 and depth < nanopb.prefs.max_depth and wire_ok(tvb, pos, len) then
                    local probe = item:add(f_field, tvb(pos, len), "as message")
                    probe:set_text("as message?")
                    decode_message(tvb, pos, len, nil, probe, depth + 1, pinfo)
                end
            end
            pos = pos + len
        elseif wire == 0 or wire == 1 or wire == 5 then
            local used
            if fd then
                used = decode_scalar(tvb, pos, limit, wire, fd, tree, msg_name, number)
            else
                local raw = { name = "field_" .. number, type = (wire == 0 and T.UINT64)
                    or (wire == 1 and T.FIXED64) or T.FIXED32 }
                used = decode_scalar(tvb, pos, limit, wire, raw, tree, nil, number)
            end
            if not used then
                tree:add_proto_expert_info(e_malformed, "Truncated value for field " .. number)
                return false
            end
            pos = pos + used
        else
            tree:add_proto_expert_info(e_malformed,
                string.format("Unsupported wire type %d for field %d", wire, number))
            return false
        end
    end
    return true
end

-- ---------------------------------------------------------------------------
-- Validation
--
-- A second pass over the packet collects field values the way nanopb's
-- pb_decode stores them, then applies the validate.proto rules exported in
-- the schema with the semantics of pb_validate.c and the code generated by
-- nanopb-validate: a packet is DROPPED if pb_decode would fail or a rule is
-- violated. Rules nanopb-validate cannot enforce are listed as not checked.
--
-- Only Lua 5.2 arithmetic is used. 64-bit integers are compared as
-- order-preserving 16-digit hex keys (signed ones offset by 2^63), matching
-- the keys the backend writes for rule constants.
-- ---------------------------------------------------------------------------

local TIMESTAMP = "google.protobuf.Timestamp"
local TWO31 = 2147483648
local TWO32 = 4294967296
local SIGNED64 = { [T.INT64] = true, [T.SINT64] = true, [T.SFIXED64] = true }
local UNSIGNED64 = { [T.UINT64] = true, [T.FIXED64] = true }

-- Varint at pos as 32-bit halves (lo, hi) and the next position.
local function varint_halves(tvb, pos, limit)
    local lo, hi, shift = 0, 0, 0
    while pos < limit and shift < 70 do
        local b = tvb(pos, 1):uint()
        pos = pos + 1
        local v = b % 128
        if shift < 28 then
            lo = lo + v * 2 ^ shift
        elseif shift == 28 then
            lo = lo + (v % 16) * 2 ^ 28
            hi = hi + math.floor(v / 16)
        else
            hi = hi + v * 2 ^ (shift - 32)
        end
        if b < 128 then return lo, hi % TWO32, pos end
        shift = shift + 7
    end
    return nil
end

local function ukey(lo, hi) return string.format("%08x%08x", hi, lo) end
local function skey(lo, hi) return string.format("%08x%08x", (hi + TWO31) % TWO32, lo) end
local SKEY_ZERO, UKEY_ZERO = skey(0, 0), ukey(0, 0)

local function zigzag_halves(lo, hi)
    local odd = lo % 2
    local nlo = math.floor(lo / 2) + (hi % 2) * TWO31
    local nhi = math.floor(hi / 2)
    if odd == 1 then return TWO32 - 1 - nlo, TWO32 - 1 - nhi end
    return nlo, nhi
end

local function signed32(lo)
    if lo >= TWO31 then return lo - TWO32 end
    return lo
end

-- Approximate number of a signed key (exact below 2^53, e.g. timestamps).
local function skey_number(key)
    return (tonumber(key:sub(1, 8), 16) - TWO31) * TWO32 + tonumber(key:sub(9), 16)
end

local function key_text(key, signed)
    if signed then
        local top = (tonumber(key:sub(1, 1), 16) + 8) % 16
        local ok, v = pcall(Int64.fromhex, string.format("%x", top) .. key:sub(2))
        if ok and v then return tostring(v) end
        return string.format("%.0f", skey_number(key))
    end
    local ok, v = pcall(UInt64.fromhex, key)
    if ok and v then return tostring(v) end
    return "0x" .. key
end

-- Value of a scalar field as validation compares it, and the next position;
-- nil and an error id if pb_decode would fail.
local function scalar_value(fd, wire, tvb, pos, limit)
    local t = fd.type
    if wire == 0 then
        if not VARINT_TYPES[t] then return nil, "decode.wire_type" end
        local lo, hi, np = varint_halves(tvb, pos, limit)
        if not lo then return nil, "decode.malformed" end
        if t == T.UINT64 then return ukey(lo, hi), np end
        if t == T.INT64 then return skey(lo, hi), np end
        if t == T.SINT64 then return skey(zigzag_halves(lo, hi)), np end
        if t == T.BOOL then return lo ~= 0 or hi ~= 0, np end
        if t == T.UINT32 then
            if hi ~= 0 then return nil, "decode.int_range" end
            return lo, np
        end
        if t == T.SINT32 then
            if hi ~= 0 then return nil, "decode.int_range" end
            if lo % 2 == 0 then return lo / 2, np end
            return -(lo + 1) / 2, np
        end
        -- int32 / enum: a sign-extended 64-bit varint that must fit 32 bits.
        local neg = lo >= TWO31
        if (neg and hi ~= TWO32 - 1) or (not neg and hi ~= 0) then return nil, "decode.int_range" end
        return signed32(lo), np
    elseif wire == 5 then
        if not FIXED32_TYPES[t] then return nil, "decode.wire_type" end
        if pos + 4 > limit then return nil, "decode.malformed" end
        local r = tvb(pos, 4)
        if t == T.FLOAT then return r:le_float(), pos + 4 end
        if t == T.SFIXED32 then return r:le_int(), pos + 4 end
        return r:le_uint(), pos + 4
    elseif wire == 1 then
        if not FIXED64_TYPES[t] then return nil, "decode.wire_type" end
        if pos + 8 > limit then return nil, "decode.malformed" end
        if t == T.DOUBLE then return tvb(pos, 8):le_float(), pos + 8 end
        local lo, hi = tvb(pos, 4):le_uint(), tvb(pos + 4, 4):le_uint()
        if t == T.SFIXED64 then return skey(lo, hi), pos + 8 end
        return ukey(lo, hi), pos + 8
    end
    return nil, "decode.wire_type"
end

-- C strings stop at the first NUL.
local function cstr(s)
    local z = s:find("\0", 1, true)
    if z then return s:sub(1, z - 1) end
    return s
end

local function join_path(path, name)
    if path == "" then return name end
    return path .. "." .. name
end

-- Collect the fields of message `msg_name` at offset/length into a state
-- table; decode failures are appended to `errors` (with their path).
-- `protocol` (protocol Decode As only): { name = ..., messages = set } plus the
-- current Any nesting level `any_depth`, checked like <protocol>_filter_udp.
local MAX_ANY_DEPTH = 4  -- PB_VALIDATE_FILTER_MAX_ANY_DEPTH

local function collect(tvb, offset, length, msg_name, depth, path, errors, with_any, protocol, any_depth)
    any_depth = any_depth or 0
    local msg = schema.messages[msg_name]
    local st = { msg = msg_name, offset = offset, length = length, fields = {}, which = {} }
    local function fail(id, detail, off, len, where)
        errors[#errors + 1] = { path = where or path, id = id, detail = detail,
                                offset = off or offset, length = len or length }
    end
    if depth > nanopb.prefs.max_depth then
        fail("decode.depth", "nesting deeper than " .. nanopb.prefs.max_depth)
        return st
    end
    local function add(number, fd, item)
        local list = st.fields[number]
        if fd.label == LABEL_REPEATED and list then
            list[#list + 1] = item
        else
            st.fields[number] = { item }
        end
        if fd.oneof then st.which[fd.oneof] = number end
    end

    local limit = offset + length
    local pos = offset
    while pos < limit do
        local start = pos
        local klo, khi, kp = varint_halves(tvb, pos, limit)
        if not klo then
            fail("decode.malformed", "truncated field key", start, limit - start)
            return st
        end
        pos = kp
        local number = math.floor(klo / 8) + khi * 536870912
        local wire = klo % 8
        if number == 0 then
            fail("decode.malformed", "field number 0", start, pos - start)
            return st
        end
        local fd = msg and msg.fields[number]
        local fpath = fd and join_path(path, fd.name) or path
        if wire == 2 then
            local len, lhi, lp = varint_halves(tvb, pos, limit)
            if not len or lhi ~= 0 or lp + len > limit then
                fail("decode.malformed", "length exceeds message", start, limit - start)
                return st
            end
            pos = lp
            if fd and fd.storage ~= "ignore" then
                local t = fd.type
                if t == T.STRING or t == T.BYTES then
                    local raw = len > 0 and tvb(pos, len):raw() or ""
                    if fd.storage == "static" and fd.max_size then
                        if len > fd.max_size then
                            fail("nanopb.max_size", string.format("%d bytes, max_size %d", len, fd.max_size),
                                start, pos + len - start, fpath)
                        elseif fd.fixed_length and len ~= fd.max_size then
                            fail("nanopb.fixed_length", string.format("%d bytes, fixed length %d", len, fd.max_size),
                                start, pos + len - start, fpath)
                        end
                    end
                    add(number, fd, { v = raw, offset = start, length = pos + len - start,
                                      data_offset = pos, data_length = len })
                elseif t == T.MESSAGE then
                    local child = collect(tvb, pos, len, fd.type_name, depth + 1, fpath, errors, with_any,
                        protocol, any_depth)
                    add(number, fd, { child = child, offset = start, length = pos + len - start })
                elseif fd.label == LABEL_REPEATED and
                        (VARINT_TYPES[t] or FIXED32_TYPES[t] or FIXED64_TYPES[t]) then
                    local elem_wire = VARINT_TYPES[t] and 0 or (FIXED32_TYPES[t] and 5 or 1)
                    local p = pos
                    while p < pos + len do
                        local v, np = scalar_value(fd, elem_wire, tvb, p, pos + len)
                        if v == nil then
                            fail(np, "bad packed element", p, pos + len - p, fpath)
                            return st
                        end
                        add(number, fd, { v = v, offset = p, length = np - p })
                        p = np
                    end
                else
                    fail("decode.wire_type", "length-delimited data for " .. fd.name, start, pos + len - start, fpath)
                    return st
                end
            end
            pos = pos + len
        elseif wire == 0 or wire == 1 or wire == 5 then
            if fd and fd.storage ~= "ignore" then
                local v, np = scalar_value(fd, wire, tvb, pos, limit)
                if v == nil then
                    fail(np, "value of " .. fd.name, start, limit - start, fpath)
                    return st
                end
                add(number, fd, { v = v, offset = start, length = np - start })
                pos = np
            else
                local skip = { [1] = 8, [5] = 4 }
                if wire == 0 then
                    local lo, _, np = varint_halves(tvb, pos, limit)
                    if not lo then
                        fail("decode.malformed", "truncated varint", start, limit - start)
                        return st
                    end
                    pos = np
                else
                    pos = pos + skip[wire]
                    if pos > limit then
                        fail("decode.malformed", "truncated value", start, limit - start)
                        return st
                    end
                end
            end
        else
            fail("decode.malformed", string.format("unsupported wire type %d", wire), start, limit - start)
            return st
        end
    end

    if msg then
        for number, fd in pairs(msg.fields) do
            local list = st.fields[number]
            if fd.label == LABEL_REPEATED and fd.storage == "static" and fd.max_count and list
                    and #list > fd.max_count then
                fail("nanopb.max_count", string.format("%d items, max_count %d", #list, fd.max_count),
                    nil, nil, join_path(path, fd.name))
            end
            if fd.presence == "required" and not list then
                fail("decode.missing_required", "missing required field " .. fd.name, nil, nil,
                    join_path(path, fd.name))
            end
        end
    end

    if msg_name == ANY then
        local url = st.fields[1] and st.fields[1][1].v or ""
        url = cstr(url)
        st.any_url = url
        local type_name = url:match("([^/]+)$")
        local value = st.fields[2] and st.fields[2][1]
        st.any_type = type_name
        if protocol then
            -- The type_url is the opcode: only messages of the protocol, nested
            -- at most MAX_ANY_DEPTH levels, and the payload is always checked.
            if any_depth >= MAX_ANY_DEPTH then
                fail("filter.depth", string.format("google.protobuf.Any nested more than %d levels", MAX_ANY_DEPTH))
            elseif not (type_name and protocol.messages[type_name]) then
                fail("filter.unknown_type", string.format("type_url %q is not a message of protocol %s",
                    url, protocol.name))
            else
                st.any_payload = collect(tvb, value and value.data_offset or offset + length,
                    value and value.data_length or 0, type_name, depth + 1, path .. "<" .. type_name .. ">",
                    errors, true, protocol, any_depth + 1)
            end
        elseif with_any and type_name and schema.messages[type_name] then
            st.any_payload = collect(tvb, value and value.data_offset or offset + length, value and value.data_length or 0,
                type_name, depth + 1, path .. "<" .. type_name .. ">", errors, with_any)
        end
    end
    return st
end

-- Format checks, ported from pb_validate.c.
local function is_digit(c) return c >= 48 and c <= 57 end
local function is_alnum(c) return is_digit(c) or (c >= 65 and c <= 90) or (c >= 97 and c <= 122) end
local function is_hex(c) return is_digit(c) or (c >= 65 and c <= 70) or (c >= 97 and c <= 102) end

local function is_hostname_label(s, i, j)
    local len = j - i + 1
    if len <= 0 or len > 63 then return false end
    if s:byte(i) == 45 or s:byte(j) == 45 then return false end
    for k = i, j do
        local c = s:byte(k)
        if c > 127 or not (is_alnum(c) or c == 45) then return false end
    end
    return true
end

local function is_hostname(s)
    local len = #s
    if len == 0 or len > 253 then return false end
    if s:byte(1) == 46 or s:byte(len) == 46 then return false end
    local start = 1
    for i = 1, len + 1 do
        local c = s:byte(i)
        if i == len + 1 or c == 46 then
            if i == start then return false end
            if not is_hostname_label(s, start, i - 1) then return false end
            start = i + 1
        elseif c <= 32 or c == 127 then
            return false
        end
    end
    return true
end

local function is_email(s)
    local len = #s
    if len < 3 then return false end
    local at
    for i = 1, len do
        local c = s:byte(i)
        if c <= 32 or c == 127 then return false end
        if c == 64 then
            if at then return false end
            at = i
        end
    end
    if not at or at == 1 or at == len then return false end
    if s:byte(1) == 46 or s:byte(at - 1) == 46 then return false end
    for i = 2, at - 1 do
        if s:byte(i) == 46 and s:byte(i - 1) == 46 then return false end
    end
    return is_hostname(s:sub(at + 1))
end

local function is_ipv4(s)
    local len = #s
    if len < 7 or len > 15 then return false end
    local start, parts = 1, 0
    for i = 1, len + 1 do
        local c = s:byte(i)
        if i == len + 1 or c == 46 then
            if parts > 3 or i == start then return false end
            local v = 0
            for k = start, i - 1 do
                local d = s:byte(k)
                if not is_digit(d) then return false end
                v = v * 10 + d - 48
                if v > 255 then return false end
            end
            parts = parts + 1
            start = i + 1
        elseif not is_digit(c) then
            return false
        end
    end
    return parts == 4
end

local function is_ipv6(s)
    local len = #s
    if len < 2 then return false end
    local function ch(i) return s:byte(i + 1) end  -- 0-based, as in the C code
    local i, start, hextets = 0, 0, 0
    local compress, after_compress = false, false
    if ch(0) == 58 then
        if 1 >= len or ch(1) ~= 58 then return false end
        i = 2
        start = i
        compress, after_compress = true, true
        if i == len then return true end
    end
    while i <= len do
        if i == len or ch(i) == 58 then
            if i == start then
                if i == len then
                    if after_compress then break end
                    return false
                end
                if compress then return false end
                compress, after_compress = true, true
                i = i + 1
                start = i
            else
                after_compress = false
                local has_dot = false
                for k = start, i - 1 do
                    if ch(k) == 46 then has_dot = true break end
                end
                if has_dot then
                    if not is_ipv4(s:sub(start + 1, i)) then return false end
                    hextets = hextets + 2
                    break
                end
                local seglen = i - start
                if seglen == 0 or seglen > 4 then return false end
                for k = start, i - 1 do
                    if not is_hex(ch(k)) then return false end
                end
                hextets = hextets + 1
                start = i + 1
                i = i + 1
            end
        else
            i = i + 1
        end
    end
    if compress then return hextets < 8 end
    return hextets == 8
end

local function default_value(fd)
    local t = fd.type
    if SIGNED64[t] then return SKEY_ZERO end
    if UNSIGNED64[t] then return UKEY_ZERO end
    if t == T.BOOL then return false end
    if t == T.STRING or t == T.BYTES then return "" end
    return 0
end

local function show_value(fd, v)
    local t = fd.type
    if t == T.STRING or t == T.BYTES then
        local text = (t == T.STRING) and cstr(v) or v
        text = text:gsub("[%c\128-\255\"\\]", function(c) return string.format("\\x%02x", c:byte()) end)
        return '"' .. text .. '"'
    end
    if SIGNED64[t] then return key_text(v, true) end
    if UNSIGNED64[t] then return key_text(v, false) end
    if type(v) == "number" and t ~= T.FLOAT and t ~= T.DOUBLE then return string.format("%.0f", v) end
    return tostring(v)
end

local function show_const(fd, rule)
    if rule.key then return key_text(rule.key, SIGNED64[fd.type]) end
    if rule.keys or rule.list then
        local parts = {}
        for _, k in ipairs(rule.keys or rule.list) do
            parts[#parts + 1] = rule.keys and key_text(k, SIGNED64[fd.type]) or show_value(fd, k)
        end
        return "{" .. table.concat(parts, ", ") .. "}"
    end
    return show_value(fd, rule.v)
end

local COMPARE = {
    GT = function(a, b) return a > b end, GTE = function(a, b) return a >= b end,
    LT = function(a, b) return a < b end, LTE = function(a, b) return a <= b end,
    EQ = function(a, b) return a == b end,
}
local COMPARE_TEXT = { GT = ">", GTE = ">=", LT = "<", LTE = "<=", EQ = "==" }

local function member(list, v)
    for _, x in ipairs(list) do
        if x == v then return true end
    end
    return false
end

-- Check one value against one rule. Returns ok, text describing the rule;
-- ok is nil for rule kinds this dissector does not evaluate.
local function check_value(rule, fd, value)
    local kind, t = rule.kind, fd.type
    if t == T.STRING then
        local s = cstr(value)
        if kind == "MIN_LEN" then return #s >= rule.v, "length >= " .. rule.v end
        if kind == "MAX_LEN" then return #s <= rule.v, "length <= " .. rule.v end
        if kind == "EQ" then return s == cstr(rule.v), "== " .. show_const(fd, rule) end
        if kind == "PREFIX" then
            local p = cstr(rule.v)
            return #s >= #p and s:sub(1, #p) == p, "prefix " .. show_const(fd, rule)
        end
        if kind == "SUFFIX" then
            local p = cstr(rule.v)
            return #s >= #p and s:sub(#s - #p + 1) == p, "suffix " .. show_const(fd, rule)
        end
        if kind == "CONTAINS" then
            return s:find(cstr(rule.v), 1, true) ~= nil, "contains " .. show_const(fd, rule)
        end
        if kind == "ASCII" then return not s:find("[\128-\255]"), "ASCII only" end
        if kind == "EMAIL" then return is_email(s), "email address" end
        if kind == "HOSTNAME" then return is_hostname(s), "hostname" end
        if kind == "IPV4" then return is_ipv4(s), "IPv4 address" end
        if kind == "IPV6" then return is_ipv6(s), "IPv6 address" end
        if kind == "IP" then return is_ipv4(s) or is_ipv6(s), "IP address" end
        if kind == "IN" or kind == "NOT_IN" then
            local found = false
            for _, x in ipairs(rule.list) do
                if cstr(x) == s then found = true break end
            end
            if kind == "IN" then return found, "in " .. show_const(fd, rule) end
            return not found, "not in " .. show_const(fd, rule)
        end
        return nil
    end
    if t == T.BYTES then
        if kind == "MIN_LEN" then return #value >= rule.v, "length >= " .. rule.v end
        if kind == "MAX_LEN" then return #value <= rule.v, "length <= " .. rule.v end
        if kind == "EQ" then return value == rule.v, "== " .. show_const(fd, rule) end
        local p = rule.v
        if kind == "PREFIX" then return #p <= #value and value:sub(1, #p) == p, "prefix " .. show_const(fd, rule) end
        if kind == "SUFFIX" then
            return #p <= #value and value:sub(#value - #p + 1) == p, "suffix " .. show_const(fd, rule)
        end
        if kind == "CONTAINS" then
            return #p <= #value and value:find(p, 1, true) ~= nil, "contains " .. show_const(fd, rule)
        end
        if kind == "IN" then return member(rule.list, value), "in " .. show_const(fd, rule) end
        if kind == "NOT_IN" then return not member(rule.list, value), "not in " .. show_const(fd, rule) end
        return nil
    end
    if kind == "ENUM_DEFINED" then
        local values = schema.enums[fd.type_name]
        return values ~= nil and values[value] ~= nil, "defined enum value"
    end
    if COMPARE[kind] then
        local expected = rule.key
        if expected == nil then expected = rule.v end  -- rule.v may be false
        return COMPARE[kind](value, expected), COMPARE_TEXT[kind] .. " " .. show_const(fd, rule)
    end
    if kind == "IN" then return member(rule.keys or rule.list, value), "in " .. show_const(fd, rule) end
    if kind == "NOT_IN" then return not member(rule.keys or rule.list, value), "not in " .. show_const(fd, rule) end
    return nil
end

local function sorted_numbers(t)
    local numbers = {}
    for n in pairs(t) do numbers[#numbers + 1] = n end
    table.sort(numbers)
    return numbers
end

local function now_key(ctx)
    return skey(ctx.now % TWO32, math.floor(ctx.now / TWO32))
end

local validate_state  -- forward

local function violation(ctx, path, item, id, detail, st)
    ctx.violations[#ctx.violations + 1] = {
        path = path, id = id, detail = detail,
        offset = item and item.offset or st.offset, length = item and item.length or st.length,
    }
end

local function unchecked(ctx, path, id, why)
    ctx.unchecked[#ctx.unchecked + 1] = string.format("%s: %s (%s)", path, id, why)
end

-- Rules of an Any field (type_url allow / deny lists) and of a Timestamp field.
local function check_special(rule, fd, item, ctx)
    local child = item.child
    if rule.kind == "ANY_IN" or rule.kind == "ANY_NOT_IN" then
        local found = member(rule.list, child and child.any_url or "")
        if rule.kind == "ANY_IN" then return found, "type_url in " .. show_const(fd, rule) end
        return not found, "type_url not in " .. show_const(fd, rule)
    end
    local seconds = SKEY_ZERO
    local list = child and child.fields[1]
    if list then seconds = list[#list].v end
    local now = now_key(ctx)
    if rule.kind == "TIMESTAMP_GT_NOW" then return seconds > now, "after the capture time" end
    if rule.kind == "TIMESTAMP_LT_NOW" then return seconds < now, "before the capture time" end
    if rule.kind == "TIMESTAMP_WITHIN" then
        local diff = math.abs(skey_number(seconds) - ctx.now)
        return diff <= rule.seconds, string.format("within %d s of the capture time", rule.seconds)
    end
    return nil
end

local SPECIAL = { ANY_IN = true, ANY_NOT_IN = true, TIMESTAMP_GT_NOW = true, TIMESTAMP_LT_NOW = true,
                  TIMESTAMP_WITHIN = true }

local function apply(ctx, ok, text, path, item, rule, fd, value, st)
    if ok == nil then
        unchecked(ctx, path, rule.id, "not supported by the dissector")
        return
    end
    ctx.checks = ctx.checks + 1
    if not ok then
        local got = (value ~= nil) and (" (got " .. show_value(fd, value) .. ")") or ""
        violation(ctx, path, item, rule.id, "must be " .. text .. got, st)
    end
end

local function recurse(ctx, fd, item, path)
    if fd.type ~= T.MESSAGE or not item.child then return end
    if fd.type_name == TIMESTAMP then return end
    if fd.type_name == ANY then
        local child = item.child
        if child.any_payload then validate_state(child.any_payload, path .. "<" .. child.any_type .. ">", ctx) end
        return
    end
    validate_state(item.child, path, ctx)
end

validate_state = function(st, path, ctx)
    local msg = schema.messages[st.msg]
    if not msg then return end
    for _, r in ipairs(msg.message_rules or {}) do
        unchecked(ctx, path ~= "" and path or st.msg, r.id, "no C enforcement")
    end
    if st.msg == ANY and st.any_payload and path == "" then
        validate_state(st.any_payload, "<" .. st.any_type .. ">", ctx)
    end
    for _, number in ipairs(sorted_numbers(msg.fields)) do
        local fd = msg.fields[number]
        local fpath = join_path(path, fd.name)
        local list = st.fields[number]
        local rules = {}
        for _, rule in ipairs(fd.rules or {}) do
            if rule.kind == "UNSUPPORTED" then
                unchecked(ctx, fpath, rule.id, "no C enforcement")
            else
                rules[#rules + 1] = rule
            end
        end
        if fd.storage == "callback" or fd.storage == "pointer" and fd.label == LABEL_REPEATED then
            -- pb_validate does not look at callback fields (or arrays of pointers).
            for _, rule in ipairs(rules) do unchecked(ctx, fpath, rule.id, fd.storage .. " field") end
        elseif fd.storage == "ignore" then
            -- not decoded at all
        elseif fd.presence == "repeated" then
            local items = list or {}
            for _, rule in ipairs(rules) do
                local kind = rule.kind
                if kind == "MIN_ITEMS" then
                    apply(ctx, #items >= rule.v, string.format("at least %d items (got %d)", rule.v, #items),
                        fpath, nil, rule, fd, nil, st)
                elseif kind == "MAX_ITEMS" then
                    apply(ctx, #items <= rule.v, string.format("at most %d items (got %d)", rule.v, #items),
                        fpath, nil, rule, fd, nil, st)
                elseif kind == "UNIQUE" then
                    if fd.type ~= T.MESSAGE then
                        local seen, dup = {}, nil
                        for i, item in ipairs(items) do
                            local k = fd.type == T.STRING and cstr(item.v) or item.v
                            if seen[k] then dup = i break end
                            seen[k] = true
                        end
                        apply(ctx, dup == nil, "unique items", dup and string.format("%s[%d]", fpath, dup - 1) or fpath,
                            dup and items[dup] or nil, rule, fd, dup and items[dup].v or nil, st)
                    end
                elseif kind == "ITEMS" then
                    for i, item in ipairs(items) do
                        local ipath = string.format("%s[%d]", fpath, i - 1)
                        for _, irule in ipairs(rule.items or {}) do
                            local ok, text = check_value(irule, fd, item.v)
                            apply(ctx, ok, text, ipath, item, irule, fd, item.v, st)
                        end
                    end
                elseif SPECIAL[kind] then
                    for i, item in ipairs(items) do
                        local ok, text = check_special(rule, fd, item, ctx)
                        apply(ctx, ok, text, string.format("%s[%d]", fpath, i - 1), item, rule, fd, nil, st)
                    end
                else
                    unchecked(ctx, fpath, rule.id, "not supported by the dissector")
                end
            end
            if fd.storage == "static" then
                for i, item in ipairs(items) do recurse(ctx, fd, item, string.format("%s[%d]", fpath, i - 1)) end
            end
        elseif fd.presence ~= "oneof" or st.which[fd.oneof] == number then
            local item = list and list[#list]
            local present = item ~= nil
            for _, rule in ipairs(rules) do
                local kind = rule.kind
                if kind == "REQUIRED" then
                    -- pb_validate only checks fields with a has_ flag.
                    if fd.presence == "explicit" then
                        apply(ctx, present, "present", fpath, nil, rule, fd, nil, st)
                    end
                elseif fd.presence == "explicit" and not present then
                    -- rules of an absent optional field are not evaluated
                elseif SPECIAL[kind] then
                    if present then
                        local ok, text = check_special(rule, fd, item, ctx)
                        apply(ctx, ok, text, fpath, item, rule, fd, nil, st)
                    end
                else
                    local value = item and item.v
                    if value == nil then value = default_value(fd) end
                    local ok, text = check_value(rule, fd, value)
                    apply(ctx, ok, text, fpath, item, rule, fd, value, st)
                end
            end
            if present then recurse(ctx, fd, item, fpath) end
        end
    end
end

-- Validate the whole packet as `msg_name`. Returns a verdict table.
local function validate_packet(tvb, msg_name, pinfo, protocol)
    local errors = {}
    local with_any = protocol ~= nil or nanopb.prefs.validate_any
    local st = collect(tvb, 0, tvb:len(), msg_name, 1, "", errors, with_any, protocol, 0)
    local ctx = { now = math.floor(pinfo.abs_ts or os.time()), violations = {}, unchecked = {}, checks = 0 }
    validate_state(st, "", ctx)
    return { errors = errors, violations = ctx.violations, unchecked = ctx.unchecked, checks = ctx.checks,
             dropped = #errors > 0 or #ctx.violations > 0 }
end

local function safe_range(tvb, offset, length)
    local total = tvb:len()
    if length and length > 0 and offset >= 0 and offset + length <= total then return tvb(offset, length) end
    return tvb()
end

-- Adds the Validation subtree; returns the Info column suffix.
local function add_validation(root, tvb, verdict, msg_name)
    local problems = #verdict.errors + #verdict.violations
    local label = verdict.dropped and "dropped" or "passed"
    local vt = root:add(f_validation, tvb(), label)
    if verdict.dropped then
        vt:set_text(string.format("Validation: DROPPED (%d %s)", problems, problems == 1 and "problem" or "problems"))
    else
        vt:set_text(string.format("Validation: PASSED (%d checks)", verdict.checks))
    end
    local function add_problem(p, expert_info)
        local where = p.path ~= "" and p.path or msg_name
        local range = safe_range(tvb, p.offset, p.length)
        local item = vt:add(f_v_rule, range, p.id)
        item:set_text(string.format("%s: %s - %s", where, p.id, p.detail))
        item:add(f_v_field, range, where)
        item:add(f_v_detail, range, p.detail)
        item:add_proto_expert_info(expert_info, string.format("%s: %s - %s", where, p.id, p.detail))
    end
    for _, e in ipairs(verdict.errors) do add_problem(e, e_decode) end
    for _, v in ipairs(verdict.violations) do add_problem(v, e_violation) end
    for _, text in ipairs(verdict.unchecked) do
        vt:add(f_v_unchecked, tvb(), text):set_text("Not checked: " .. text)
    end
    if not verdict.dropped then return " [PASSED]" end
    local first = verdict.errors[1] or verdict.violations[1]
    return string.format(" [DROPPED %s %s]", first.id, first.path ~= "" and first.path or msg_name)
end

-- Quick structural check used before trying the Any fallback.
local function looks_like_any(tvb, offset, length)
    return parse_any(tvb, offset, length) ~= nil
end

-- Stricter check for the heuristic dissector: an Any whose type is in the
-- schema and whose value is well-formed protobuf.
local function is_known_any(tvb)
    local length = tvb:len()
    if length < 4 then return false end
    local type_url, type_name, value_off, value_len = parse_any(tvb, 0, length)
    if not type_url or not type_url:find("/", 1, true) or not schema.messages[type_name] then
        return false
    end
    return value_off == nil or wire_ok(tvb, value_off, value_len)
end

-- ---------------------------------------------------------------------------
-- Dissector entry point
-- ---------------------------------------------------------------------------

local function root_message(pinfo, tvb)
    local transport = (pinfo.port_type == 3 and "udp") or (pinfo.port_type == 2 and "tcp") or nil
    if transport then
        local map = port_map[transport]
        local msg = map[pinfo.match_uint] or map[pinfo.dst_port] or map[pinfo.src_port]
        if msg then return msg end
    end
    if nanopb.prefs.default_message ~= "" then return nanopb.prefs.default_message end
    if primary_protocol() then return ANY end
    if nanopb.prefs.any_fallback and looks_like_any(tvb, 0, tvb:len()) then return ANY end
    return nil
end

local function dissect(tvb, pinfo, tree, forced_root, protocol)
    local length = tvb:len()
    if length == 0 then return 0 end
    local msg_name = forced_root or root_message(pinfo, tvb)
    if not protocol and msg_name == ANY then protocol = primary_protocol() end
    pinfo.cols.protocol = protocol and protocol.column or "NANOPB"
    local root = tree:add(protocol and protocol.proto or nanopb, tvb(),
        protocol and ("nanopb " .. protocol.name) or "nanopb Protobuf")
    if not schema_ok then root:add_proto_expert_info(e_no_schema) end

    if msg_name and not schema.messages[msg_name] then
        root:add_proto_expert_info(e_unknown_type, "Root message not in schema: " .. msg_name)
        msg_name = nil
    end
    root:append_text(": " .. (msg_name or "raw"))
    local top = root:add(f_message, tvb(), msg_name or "raw")
    top:set_text(msg_name or "raw (no schema message selected)")
    decode_message(tvb, 0, length, msg_name, top, 1, pinfo)
    local suffix = ""
    if msg_name and schema_ok and nanopb.prefs.validate then
        suffix = add_validation(root, tvb, validate_packet(tvb, msg_name, pinfo, protocol), msg_name)
    end
    local shown = msg_name or "raw"
    if protocol then
        -- Show the message the type_url selects rather than "google.protobuf.Any".
        local _, type_name = parse_any(tvb, 0, length)
        shown = protocol.name .. " " .. (type_name or "?")
    end
    pinfo.cols.info:set(string.format("nanopb %s (%d bytes)%s", shown, length, suffix))
    return length
end

function nanopb.dissector(tvb, pinfo, tree)
    return dissect(tvb, pinfo, tree, nil)
end

-- Heuristic: claim UDP/TCP payloads on unmapped ports that are a
-- google.protobuf.Any of a type known to the schema.
local function heuristic(tvb, pinfo, tree)
    if not nanopb.prefs.heuristic or not schema_ok then return false end
    if not is_known_any(tvb) then return false end
    dissect(tvb, pinfo, tree, ANY)
    return true
end

DissectorTable.get("udp.port"):add_for_decode_as(nanopb)
DissectorTable.get("tcp.port"):add_for_decode_as(nanopb)

-- Each protocol is also a Wireshark protocol named after its folder: choose
-- it with Analyze > Decode As > UDP/TCP port > FLEET (or set it as the NANOPB
-- Protocol preference). Every packet is a google.protobuf.Any whose type_url
-- selects a message of that protocol, validated like <name>_filter_udp.
for _, name in ipairs(protocol_names) do
    -- Wireshark wants a lowercase filter name; Decode As shows it uppercased.
    -- A name Wireshark already uses (e.g. a folder called "ip") gets a prefix.
    local ident = name:gsub("[^%w_]", "_"):lower()
    local desc = name .. " (nanopb protocol, Any type_url = message)"
    local ok, proto = pcall(Proto, ident, desc)
    if not ok then
        ident = "nanopb_" .. ident
        proto = Proto(ident, desc)
    end
    local set = {}
    for _, msg in ipairs(schema.protocols[name]) do set[msg] = true end
    local protocol = { name = name, messages = set, proto = proto, column = ident:upper() }
    function proto.dissector(tvb, pinfo, tree)
        return dissect(tvb, pinfo, tree, ANY, protocol)
    end
    DissectorTable.get("udp.port"):add_for_decode_as(proto)
    DissectorTable.get("tcp.port"):add_for_decode_as(proto)
    protocols[name] = protocol
end

-- Ports mapped to a protocol (written by Generate test packets), like a Decode As.
for _, e in ipairs(default_ports) do
    if e.protocol and protocols[e.protocol] then
        DissectorTable.get(e.transport .. ".port"):add(e.port, protocols[e.protocol].proto)
    end
end
nanopb:register_heuristic("udp", heuristic)
nanopb:register_heuristic("tcp", heuristic)
apply_ports()
