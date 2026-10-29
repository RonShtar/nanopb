-- Minimal stand-in for the Wireshark Lua API, enough to load and exercise
-- nanopb_any_dissector.lua and nanopb_studio.lua outside Wireshark.
-- Requires Lua 5.3+ (64-bit integers). Used by test_dissector.py via lupa.

local M = { menus = {}, windows = {}, dialog_answers = {}, tables = {} }

-- UInt64 / Int64 ----------------------------------------------------------
local U64, I64 = {}, {}
U64.__index, I64.__index = U64, I64

local function u64(v) return setmetatable({ v = v }, U64) end
local function i64(v) return setmetatable({ v = v }, I64) end
local function raw(x) if type(x) == "table" then return x.v end return math.tointeger(x) end

UInt64 = setmetatable({}, { __call = function(_, n) return u64(math.tointeger(n or 0)) end })
Int64 = setmetatable({}, { __call = function(_, n) return i64(math.tointeger(n or 0)) end })
function Int64.fromhex(h) return i64(math.tointeger(tonumber(h, 16) or 0) or 0) end
function UInt64.fromhex(h) return u64(math.tointeger(tonumber(h, 16) or 0) or 0) end

function U64:bor(o) return u64(self.v | raw(o)) end
function U64:band(o) return u64(self.v & raw(o)) end
function U64:lshift(n) return u64(self.v << n) end
function U64:rshift(n) return u64(self.v >> n) end
function U64:tohex() return string.format("%016x", self.v) end
function U64:tonumber() return self.v >= 0 and self.v or self.v + 18446744073709551616.0 end
U64.__eq = function(a, b) return a.v == b.v end
U64.__tostring = function(a)
    if a.v >= 0 then return tostring(a.v) end
    local q = (a.v >> 1) // 5
    return tostring(q) .. tostring(a.v - q * 10)
end

function I64:tonumber() return self.v end
I64.__unm = function(a) return i64(-a.v) end
I64.__sub = function(a, b) return i64(raw(a) - raw(b)) end
I64.__eq = function(a, b) return a.v == b.v end
I64.__tostring = function(a) return tostring(a.v) end

-- ByteArray / Tvb ----------------------------------------------------------
ByteArray = {}
function ByteArray.new(s)
    return setmetatable({ s = s or "" }, { __tostring = function(b)
        return (b.s:gsub(".", function(c) return string.format("%02x", c:byte()) end))
    end })
end

local Range = {}
Range.__index = Range
function Range:uint() local v = 0 for i = 1, #self.s do v = v * 256 + self.s:byte(i) end return v end
function Range:le_uint() return (string.unpack("<I" .. #self.s, self.s)) end
function Range:le_int() return (string.unpack("<i" .. #self.s, self.s)) end
-- As in Wireshark, le_float reads a 4-byte float or an 8-byte double.
function Range:le_float() return (string.unpack(#self.s == 8 and "<d" or "<f", self.s)) end
function Range:le_uint64() return u64((string.unpack("<i8", self.s))) end
function Range:le_int64() return i64((string.unpack("<i8", self.s))) end
function Range:string() return self.s end
function Range:raw() return self.s end
function Range:bytes() return ByteArray.new(self.s) end
function Range:len() return #self.s end

function M.tvb(bytes)
    return setmetatable({ bytes = bytes }, {
        __call = function(t, offset, length)
            offset = offset or 0
            length = length or (#t.bytes - offset)
            assert(offset >= 0 and length >= 0 and offset + length <= #t.bytes,
                string.format("tvb range out of bounds: %d+%d > %d", offset, length, #t.bytes))
            return setmetatable({ s = t.bytes:sub(offset + 1, offset + length) }, Range)
        end,
        __index = { len = function(t) return #t.bytes end },
    })
end

-- Tree ----------------------------------------------------------------------
local Item = {}
Item.__index = Item
local function new_item(text) return setmetatable({ text = text or "", children = {}, experts = {} }, Item) end

local function value_text(field, value)
    if field.valstring and value ~= nil and field.valstring[value] then
        return string.format("%s (%s)", field.valstring[value], tostring(value))
    end
    return tostring(value)
end

function Item:add(field, range, value)
    local text
    if field.is_proto then
        text = value or field.description
    elseif value ~= nil then
        -- Like Wireshark 3.6: bytes fields only take their value from the range.
        assert(field.kind ~= "bytes", "bytes ProtoField added with a value argument")
        text = field.name .. ": " .. value_text(field, value)
    elseif field.kind == "bytes" and range then
        text = field.name .. ": " .. tostring(ByteArray.new(range.s))
    else
        text = field.name
    end
    local child = new_item(text)
    child.field = field
    child.value = value
    self.children[#self.children + 1] = child
    return child
end
function Item:set_text(t) self.text = t return self end
function Item:append_text(t) self.text = self.text .. t return self end
function Item:add_proto_expert_info(e, text)
    self.experts[#self.experts + 1] = (e and e.abbr or "?") .. ": " .. (text or e.text)
    return self
end

function M.tree() return new_item("root") end

function M.render(item, indent, out)
    out = out or {}
    indent = indent or ""
    if item.text ~= "root" then out[#out + 1] = indent .. item.text end
    for _, e in ipairs(item.experts) do out[#out + 1] = indent .. "  !" .. e end
    for _, c in ipairs(item.children) do M.render(c, item.text == "root" and "" or indent .. "  ", out) end
    return table.concat(out, "\n")
end

-- Proto, fields, prefs ---------------------------------------------------
-- Reload Lua plugins: Wireshark drops the Lua protocols first.
function M.reload() M.protos = {} end

function Proto(name, description)
    -- Like Wireshark: a protocol name can be registered once.
    if M.protos and M.protos[name] then error("Protocol exists: " .. name) end
    local values = {}
    local prefs = setmetatable({}, {
        __newindex = function(_, k, pref) values[k] = pref.default end,
        __index = function(_, k) return values[k] end,
    })
    local p = { name = name, description = description, is_proto = true, prefs = prefs, pref_values = values }
    function p:register_heuristic(list, fn)
        M.heuristics = M.heuristics or {}
        M.heuristics[list] = fn
    end
    M.protos = M.protos or {}
    M.protos[name] = p
    return p
end

Pref = {}
for _, kind in ipairs({ "string", "bool", "uint" }) do
    Pref[kind] = function(label, default) return { label = label, default = default } end
end
function Pref.enum(label, default, _, choices)
    return { label = label, default = default, choices = choices }
end

ProtoField = setmetatable({}, { __index = function(_, kind)
    return function(abbr, name, _, valstring)
        return { abbr = abbr, name = name or abbr, kind = kind,
                 valstring = type(valstring) == "table" and valstring or nil }
    end
end })

ProtoExpert = { new = function(abbr, text) return { abbr = abbr, text = text } end }
expert = { group = setmetatable({}, { __index = function(_, k) return k end }),
           severity = setmetatable({}, { __index = function(_, k) return k end }) }
base = { DEC = "DEC", HEX = "HEX" }
ENC_UTF_8 = 0

DissectorTable = { get = function(name)
    local t = M.tables[name]
    if not t then
        t = { name = name, entries = {}, decode_as = false, decode_as_names = {} }
        function t:add(port, proto) self.entries[port] = proto end
        function t:remove(port, proto)
            if proto == nil or rawequal(self.entries[port], proto) then self.entries[port] = nil end
        end
        function t:add_for_decode_as(proto)
            self.decode_as = true
            self.decode_as_names[proto.name] = true
        end
        M.tables[name] = t
    end
    return t
end }

function M.pinfo(port_type, port)
    local info = { value = "" }
    function info:set(v) self.value = v end
    return { port_type = port_type, match_uint = port, dst_port = port, src_port = 40000, abs_ts = M.now or os.time(),
             cols = { protocol = "", info = info } }
end

-- GUI -----------------------------------------------------------------------
function gui_enabled() return true end
MENU_TOOLS_UNSORTED = 8
function register_menu(name, fn) M.menus[name] = fn end
function new_dialog(title, action, ...)
    local fields = { ... }
    for _, f in ipairs(fields) do
        if type(f) ~= "table" and type(f) ~= "string" then error("bad field") end
    end
    local answers = M.dialog_answers[title]
    assert(answers, "unexpected dialog: " .. title)
    action(table.unpack(answers, 1, #fields))
end
TextWindow = { new = function(title)
    local w = { title = title, text = "", buttons = {} }
    function w:set(t) self.text = t end
    function w:append(t) self.text = self.text .. t end
    function w:add_button(label, fn) self.buttons[label] = fn end
    M.windows[#M.windows + 1] = w
    return w
end }

return M
