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

local function load_data(path)
    local chunk = loadfile(path)
    if not chunk then return nil end
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

local fields = { f_message, f_field, f_type_url, f_unknown }

local e_malformed = ProtoExpert.new("nanopb.malformed", "Malformed protobuf data",
    expert.group.MALFORMED, expert.severity.ERROR)
local e_unknown_type = ProtoExpert.new("nanopb.any.unknown_type", "Any type not in schema",
    expert.group.UNDECODED, expert.severity.WARN)
local e_no_schema = ProtoExpert.new("nanopb.no_schema",
    "nanopb schema not found; run Tools > nanopb > Install / update dissector",
    expert.group.UNDECODED, expert.severity.NOTE)
local e_depth = ProtoExpert.new("nanopb.depth", "Maximum nesting depth reached",
    expert.group.UNDECODED, expert.severity.WARN)
nanopb.experts = { e_malformed, e_unknown_type, e_no_schema, e_depth }

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
        parts[#parts + 1] = string.format("%s:%d=%s", e.transport, e.port, e.message)
    end
    return table.concat(parts, ",")
end

nanopb.prefs.port_map = Pref.string("Port map", default_port_map_string(),
    "Comma-separated transport:port=message entries, e.g. udp:5000=pkg.Envelope,tcp:7000=pkg.Cmd")
nanopb.prefs.default_message = Pref.string("Default message", "",
    "Root message for payloads without a port map entry (e.g. with Decode As). Empty = none")
nanopb.prefs.any_fallback = Pref.bool("Treat unknown payload as Any", true,
    "Decode payloads without a root message as google.protobuf.Any")
nanopb.prefs.max_depth = Pref.uint("Maximum nesting depth", 32, "Guard against runaway recursion")

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
    if pf then
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
        if t == T.DOUBLE then value = r:le_double()
        elseif t == T.SFIXED64 then value = r:le_int64()
        else value = r:le_uint64() end
        add_scalar(tree, msg_name, number, fd, r, value, string.format("%s: %s", fd.name, tostring(value)))
        return 8
    end
    return nil
end

local function decode_any(tvb, offset, length, tree, depth, pinfo)
    -- Find type_url (1) and value (2) without building a tree first.
    local limit = offset + length
    local pos = offset
    local type_url, value_off, value_len
    while pos < limit do
        local key, klen = read_varint(tvb, pos, limit)
        if not key then return false end
        pos = pos + klen
        local number = key:rshift(3):tonumber()
        local wire = key:band(UInt64(7)):tonumber()
        if wire ~= 2 then return false end
        local len, llen = read_varint(tvb, pos, limit)
        if not len then return false end
        pos = pos + llen
        len = len:tonumber()
        if pos + len > limit then return false end
        if number == 1 then
            type_url = tvb(pos, len):string(ENC_UTF_8)
        elseif number == 2 then
            value_off, value_len = pos, len
        end
        pos = pos + len
    end
    if not type_url then return false end

    local type_name = type_url:match("([^/]+)$") or type_url
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
                local value = len > 0 and tvb(pos, len):bytes() or ByteArray.new()
                add_scalar(tree, msg_name, number, fd, whole, value,
                    string.format("%s: %s", fd.name, tostring(value)))
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

-- Quick structural check used before trying the Any fallback.
local function looks_like_any(tvb, offset, length)
    local limit = offset + length
    local pos = offset
    local seen_url = false
    while pos < limit do
        local key, klen = read_varint(tvb, pos, limit)
        if not key then return false end
        pos = pos + klen
        local number = key:rshift(3):tonumber()
        if key:band(UInt64(7)):tonumber() ~= 2 or (number ~= 1 and number ~= 2) then return false end
        local len, llen = read_varint(tvb, pos, limit)
        if not len then return false end
        pos = pos + llen + len:tonumber()
        if pos > limit then return false end
        if number == 1 then seen_url = true end
    end
    return seen_url
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
    if nanopb.prefs.any_fallback and looks_like_any(tvb, 0, tvb:len()) then return ANY end
    return nil
end

function nanopb.dissector(tvb, pinfo, tree)
    local length = tvb:len()
    if length == 0 then return 0 end
    pinfo.cols.protocol = "NANOPB"

    local msg_name = root_message(pinfo, tvb)
    local root = tree:add(nanopb, tvb(), "nanopb Protobuf")
    if not schema_ok then root:add_proto_expert_info(e_no_schema) end

    if msg_name and not schema.messages[msg_name] then
        root:add_proto_expert_info(e_unknown_type, "Root message not in schema: " .. msg_name)
        msg_name = nil
    end
    root:append_text(": " .. (msg_name or "raw"))
    local top = root:add(f_message, tvb(), msg_name or "raw")
    top:set_text(msg_name or "raw (no schema message selected)")
    decode_message(tvb, 0, length, msg_name, top, 1, pinfo)
    pinfo.cols.info:set(string.format("nanopb %s (%d bytes)", msg_name or "raw", length))
    return length
end

DissectorTable.get("udp.port"):add_for_decode_as(nanopb)
DissectorTable.get("tcp.port"):add_for_decode_as(nanopb)
apply_ports()
