-- nanopb_studio.lua
--
-- Tools > nanopb menu for Wireshark: generate merged nanopb C code (with
-- validation) and encoded sample data from a directory of .proto units, and
-- install/update nanopb_any_dissector.lua with a matching schema.
--
-- Every action asks only for the input (protos) and output directories, then
-- lists the units found in the input so you can pick which ones to generate.
--
-- All work is done by tools/wireshark/backend/nanopb_wireshark.py in the
-- nanopb checkout recorded by `nanopb_wireshark.py install-studio`; this file
-- only collects input and shows output. The checkout, the Python executable and
-- the last used directories are kept in nanopb/studio_config.luadata next to
-- this file.
--
-- Works with Wireshark 3.6+ (Lua 5.2 - 5.4) on Windows and Linux.

if not gui_enabled() then return end

if set_plugin_info then
    set_plugin_info({
        version = "1.1.0",
        description = "nanopb code / sample data generator and dissector installer",
        repository = "https://github.com/nanopb/nanopb",
    })
end

local IS_WINDOWS = package.config:sub(1, 1) == "\\"
local SEP = IS_WINDOWS and "\\" or "/"

local function script_dir()
    local src = debug.getinfo(1, "S").source
    if src:sub(1, 1) == "@" then src = src:sub(2) end
    return src:match("^(.*)[/\\]") or "."
end

local PLUGINS_DIR = script_dir()
local DATA_DIR = PLUGINS_DIR .. SEP .. "nanopb"
local CONFIG_PATH = DATA_DIR .. SEP .. "studio_config.luadata"

local function join(...)
    return table.concat({ ... }, SEP)
end

-- ---------------------------------------------------------------------------
-- Stored state
-- ---------------------------------------------------------------------------

local KEYS = { "python", "project", "nanopb_root", "protos_root", "output_dir", "extra_includes", "port_map" }

local config = {
    python = IS_WINDOWS and "python" or "python3",
    project = "",
    nanopb_root = "",
    protos_root = "",
    output_dir = "",
    extra_includes = "",
    port_map = "",
}

local function load_config()
    -- Wireshark's loadfile raises an error for missing files.
    local f = io.open(CONFIG_PATH, "r")
    if not f then return end
    f:close()
    local loaded, chunk = pcall(loadfile, CONFIG_PATH)
    if not loaded or not chunk then return end
    local ok, saved = pcall(chunk)
    if ok and type(saved) == "table" then
        for _, k in ipairs(KEYS) do
            if type(saved[k]) == "string" then config[k] = saved[k] end
        end
    end
end

local function mkdir(path)
    if IS_WINDOWS then
        os.execute('if not exist "' .. path .. '" mkdir "' .. path .. '"')
    else
        os.execute("mkdir -p '" .. path:gsub("'", "'\\''") .. "'")
    end
end

local function save_config()
    mkdir(DATA_DIR)
    local f, err = io.open(CONFIG_PATH, "w")
    if not f then return false, err end
    f:write("-- nanopb studio state (written by install-studio and the Tools > nanopb dialogs)\nreturn {\n")
    for _, k in ipairs(KEYS) do
        f:write(string.format("  %s = %q,\n", k, config[k] or ""))
    end
    f:write("}\n")
    f:close()
    return true
end

load_config()

local function output_dir()
    if config.output_dir ~= "" then return config.output_dir end
    if config.protos_root ~= "" then return config.protos_root .. SEP .. ".." .. SEP .. "nanopb_out" end
    return ""
end

-- ---------------------------------------------------------------------------
-- Running the backend
-- ---------------------------------------------------------------------------

local function quote(arg)
    if IS_WINDOWS then
        -- Backslashes before a quote must be doubled for CommandLineToArgv.
        local escaped = arg:gsub('(\\*)"', '%1%1\\"'):gsub("(\\+)$", "%1%1")
        return '"' .. escaped .. '"'
    end
    return "'" .. arg:gsub("'", "'\\''") .. "'"
end

-- The copy made by install-studio, or a checkout when installed with --dev.
local function project_root()
    if config.nanopb_root ~= "" then return config.nanopb_root end
    if config.project ~= "" then return config.project end
    return join(DATA_DIR, "project")
end

local function backend_path()
    return join(project_root(), "tools", "wireshark", "backend", "nanopb_wireshark.py")
end

local function file_exists(path)
    local f = io.open(path, "r")
    if f then f:close() return true end
    return false
end

-- Run the backend with a list of arguments. Returns ok, output text.
local function run_backend(args)
    if not file_exists(backend_path()) then
        return false, "nanopb backend not found at " .. backend_path() .. ".\n" ..
            "From the nanopb checkout run\n\n" ..
            "    python tools/wireshark/backend/nanopb_wireshark.py install-studio\n\n" ..
            "and reload Lua plugins (Ctrl+Shift+L)."
    end
    local parts = { quote(config.python), quote(backend_path()), "--nanopb-root", quote(project_root()) }
    for _, a in ipairs(args) do parts[#parts + 1] = quote(a) end
    local cmd = table.concat(parts, " ") .. " 2>&1"
    -- cmd.exe strips the first and last quote of the whole line.
    if IS_WINDOWS then cmd = '"' .. cmd .. '"' end
    local pipe = io.popen(cmd, "r")
    if not pipe then return false, "could not start: " .. cmd end
    local out = pipe:read("*a") or ""
    pipe:close()
    local status = out:match("__EXIT__=(%d+)%s*$")
    out = out:gsub("\n?__EXIT__=%d+%s*$", "")
    if status == nil then
        return false, "Backend did not run. Check the Python path in " .. CONFIG_PATH .. "\n\n" ..
            cmd .. "\n\n" .. out
    end
    return status == "0", out
end

local function add_common(args)
    args[#args + 1] = "--protos-root"
    args[#args + 1] = config.protos_root
    -- Not asked for in the dialogs; can be set by hand in the state file.
    for inc in string.gmatch(config.extra_includes or "", "[^;]+") do
        inc = inc:match("^%s*(.-)%s*$")
        if inc ~= "" then
            args[#args + 1] = "-I"
            args[#args + 1] = inc
        end
    end
    return args
end

local function open_folder(path)
    if browser_open_url then
        local url = path:gsub("\\", "/")
        if url:sub(1, 1) ~= "/" then url = "/" .. url end
        browser_open_url("file://" .. url)
    elseif IS_WINDOWS then
        os.execute('start "" ' .. quote(path))
    else
        os.execute("xdg-open " .. quote(path) .. " >/dev/null 2>&1 &")
    end
end

-- Result window; `buttons` is a list of { label, function } shown on success.
local function show(title, ok, text, folder, buttons)
    local win = TextWindow.new(title)
    win:set((ok and "OK\n\n" or "FAILED\n\n") .. text)
    if ok then
        for _, b in ipairs(buttons or {}) do win:add_button(b[1], b[2]) end
        if folder then win:add_button("Open output folder", function() open_folder(folder) end) end
    end
end

-- Minimal readers for the backend's JSON output.
local JSON_ESCAPES = { n = "\n", t = "\t", r = "\r", ['"'] = '"', ["\\"] = "\\", ["/"] = "/" }

local function json_string(text, key)
    local _, start = text:find('"' .. key .. '"%s*:%s*"')
    if not start then return nil end
    -- Up to the first quote that is not escaped (the value may be empty).
    local pos = start + 1
    while pos <= #text do
        local c = text:sub(pos, pos)
        if c == "\\" then
            pos = pos + 2
        elseif c == '"' then
            return (text:sub(start + 1, pos - 1):gsub("\\(.)", JSON_ESCAPES))
        else
            pos = pos + 1
        end
    end
    return nil
end

local function json_bool(text, key)
    return text:match('"' .. key .. '"%s*:%s*(%a+)') == "true"
end

local unpack_ = table.unpack or unpack

-- Newer Wireshark versions accept {label, default} tables in new_dialog; fall
-- back to plain labels where they are rejected.
local function dialog(title, fields, action)
    local ok = pcall(new_dialog, title, action, unpack_(fields))
    if not ok then
        local labels = {}
        for i, f in ipairs(fields) do labels[i] = type(f) == "table" and f[1] or f end
        new_dialog(title, action, unpack_(labels))
    end
end

local function trim(value)
    return ((value or ""):gsub("^%s+", ""):gsub("%s+$", ""))
end

-- ---------------------------------------------------------------------------
-- Directory dialog and unit picker
-- ---------------------------------------------------------------------------

-- Ask for the input directory, and the output directory if `with_output`.
-- An empty input keeps the last one used. Values of `extra` fields are passed
-- to `action`.
local function ask_dirs(title, with_output, extra, action)
    local fields = { { "Input: protos directory (one subdirectory per unit)", config.protos_root } }
    if with_output then
        fields[#fields + 1] = { "Output directory (empty = <input>/../nanopb_out)", config.output_dir }
    end
    local first_extra = #fields + 1
    for _, f in ipairs(extra or {}) do fields[#fields + 1] = f end
    dialog(title, fields, function(...)
        local values = { ... }
        local input = trim(values[1])
        if input ~= "" then config.protos_root = input end
        if with_output then config.output_dir = trim(values[2]) end
        if config.protos_root == "" then
            show(title, false, "Enter the input protos directory.")
            return
        end
        save_config()
        action(unpack_(values, first_extra, #fields))
    end)
end

local function parse_unit_names(text)
    local list = text:match('"units"%s*:%s*%[(.-)%]')
    local names = {}
    for name in string.gmatch(list or "", '"(.-)"') do
        names[#names + 1] = (name:gsub("\\\\", "\\"))
    end
    -- "merged_into": { "shared": [ "fleet" ] } -> merged["shared"] = "fleet"
    local merged = {}
    local object = text:match('"merged_into"%s*:%s*(%b{})') or ""
    for name, users in string.gmatch(object, '"([^"]+)"%s*:%s*%[(.-)%]') do
        local list_users = {}
        for user in string.gmatch(users, '"(.-)"') do list_users[#list_users + 1] = user end
        merged[name] = table.concat(list_users, ", ")
    end
    return names, merged
end

-- Show the units of the input directory as a toggle list. `generate` gets the
-- comma separated selection and returns ok, output text and optionally extra
-- result-window buttons and a function to run after the window is shown.
-- Units of the protos directory and which ones other units import, read
-- directly with Wireshark's Dir API: listing them needs no Python process.
-- Returns nil where Dir is not available (very old Wireshark).
local function scan_units(root)
    if not (Dir and Dir.open and Dir.exists) then return nil end
    if not Dir.exists(root) then return nil, root .. " is not a directory" end
    local names = {}
    for entry in Dir.open(root) do
        local path = join(root, entry)
        if entry ~= "." and entry ~= ".." and Dir.exists(path) then
            local has_proto = false
            for _ in Dir.open(path, ".proto") do has_proto = true break end
            if has_proto then names[#names + 1] = entry end
        end
    end
    table.sort(names)
    local is_unit, merged = {}, {}
    for _, name in ipairs(names) do is_unit[name] = true end
    for _, name in ipairs(names) do
        for file in Dir.open(join(root, name), ".proto") do
            local f = io.open(join(root, name, file), "r")
            if f then
                local text = f:read("*a") or ""
                f:close()
                for path in text:gmatch('import%s+[%a]*%s*"([^"]+)"') do
                    local other = path:match("^([^/]+)/")
                    if other and other ~= name and is_unit[other] then
                        local users = merged[other] or {}
                        local known = false
                        for _, u in ipairs(users) do known = known or u == name end
                        if not known then users[#users + 1] = name end
                        merged[other] = users
                    end
                end
            end
        end
    end
    for other, users in pairs(merged) do merged[other] = table.concat(users, ", ") end
    return names, merged
end

local function pick_units(title, generate)
    local names, merged = scan_units(config.protos_root)
    if names == nil and merged then
        show(title, false, merged)
        return
    end
    if names == nil then
        local ok, text = run_backend(add_common({ "units", "--names-only" }))
        if not ok then
            show(title, false, text)
            return
        end
        names, merged = parse_unit_names(text)
    end
    if #names == 0 then
        show(title, false, "No subdirectory of " .. config.protos_root .. " contains .proto files.")
        return
    end
    -- A unit imported by another is already merged into that one's .c/.h;
    -- generating both would link the same code twice.
    local selected = {}
    for _, name in ipairs(names) do selected[name] = merged[name] == nil end

    local win = TextWindow.new(title .. ": choose units")
    local function render(note)
        local lines = {
            "Click a unit to select or deselect it, then press Generate.",
            "Wireshark does not respond for a few seconds while it generates.",
            "",
            "Input:  " .. config.protos_root,
            "Output: " .. output_dir(),
            "",
        }
        for _, name in ipairs(names) do
            local note = merged[name] and ("   (already merged into " .. merged[name] .. ")") or ""
            lines[#lines + 1] = (selected[name] and "  [x] " or "  [ ] ") .. name .. note
        end
        if note then
            lines[#lines + 1] = ""
            lines[#lines + 1] = note
        end
        win:set(table.concat(lines, "\n"))
    end
    local function select_all(value)
        for _, name in ipairs(names) do selected[name] = value end
        render()
    end
    for _, name in ipairs(names) do
        win:add_button(name, function()
            selected[name] = not selected[name]
            render()
        end)
    end
    win:add_button("Select all", function() select_all(true) end)
    win:add_button("Select none", function() select_all(false) end)
    win:add_button("Generate", function()
        local chosen = {}
        for _, name in ipairs(names) do
            if selected[name] then chosen[#chosen + 1] = name end
        end
        if #chosen == 0 then
            render("Select at least one unit.")
            return
        end
        local done, out, buttons, after = generate(table.concat(chosen, ","))
        render(done and ("Generated: " .. table.concat(chosen, ", ")) or "FAILED, see the result window.")
        show(title, done, out, output_dir(), buttons)
        if done and after then after() end
    end)
    render()
end

-- ---------------------------------------------------------------------------
-- Menu actions
-- ---------------------------------------------------------------------------

local function gen_c()
    local title = "Generate C (merged + validation)"
    ask_dirs(title, true, nil, function()
        pick_units(title, function(units)
            -- Port-mapped messages are the protocol entrypoints that get a packet filter.
            local args = add_common({ "gen-c", "--out", output_dir(), "--unit", units })
            if config.port_map ~= "" then
                args[#args + 1] = "--port-map"
                args[#args + 1] = config.port_map
            end
            local ok, text = run_backend(args)
            if not ok then return false, text end
            return true, (json_string(text, "summary") or text) .. "\n\n" ..
                "<unit>.pb.c/.h: all messages, PB_BINDs and the packet filters (_udp/_tcp).\n" ..
                "<unit>_validate.c/.h: all pb_validate_* validators.\n" ..
                "Add all four to your project, next to the nanopb runtime.\n" ..
                "The -D values are optional: they shrink the validation buffers to what this\n" ..
                "schema needs (docs/validation_performance.md)."
        end)
    end)
end

local DROPPED_FILTER = 'nanopb.validation == "dropped"'

-- One button: valid and invalid packets of every message in one capture,
-- dissector refreshed, capture opened. Every packet is a google.protobuf.Any
-- (type_url = message) on its protocol's port, mapped like a Decode As to
-- the <protocol> dissector; each one is also written as a C array (.h) and .hex.
local function gen_packets()
    local title = "Generate test packets"
    ask_dirs(title, true, nil, function()
        pick_units(title, function(units)
            local args = add_common({ "gen-packets", "--mode", "protocol", "--out", output_dir(),
                "--unit", units, "--plugins-dir", PLUGINS_DIR })
            if config.port_map ~= "" then
                args[#args + 1] = "--port-map"
                args[#args + 1] = config.port_map
            end
            local ok, text = run_backend(args)
            if not ok then return false, text end
            local pcap = json_string(text, "pcap") or ""
            local summary = json_string(text, "summary") or text
            local picked = json_string(text, "port_map") or ""
            if config.port_map == "" and picked ~= "" then
                -- Keep the ports gen-packets picked, so the dissector and Generate C agree.
                config.port_map = picked
                save_config()
            end
            local reload = json_bool(text, "schema_changed") and reload_lua_plugins
            local notes = { summary, "" }
            if open_capture_file then
                notes[#notes + 1] = "Opening the capture. Each packet shows Validation: PASSED or DROPPED."
                notes[#notes + 1] = "Other ports: Analyze > Decode As > UDP/TCP port > FLEET (your folder name), or set it for all NANOPB"
                    .. "\ntraffic: Edit > Preferences > Protocols > NANOPB > Protocol."
            else
                notes[#notes + 1] = "Open the capture with File > Open: " .. pcap
            end
            if json_bool(text, "schema_changed") then
                notes[#notes + 1] = reload_lua_plugins and "The dissector schema changed; reloading Lua plugins."
                    or "The dissector schema changed; reload Lua plugins (Ctrl+Shift+L)."
            end
            local buttons = {}
            if set_filter and apply_filter then
                buttons[#buttons + 1] = { "Show dropped only", function()
                    set_filter(DROPPED_FILTER)
                    apply_filter()
                end }
                buttons[#buttons + 1] = { "Show all", function()
                    set_filter("")
                    apply_filter()
                end }
            end
            local function after()
                if open_capture_file and pcap ~= "" then open_capture_file(pcap, "") end
                -- Last: reloading re-runs the plugins and re-dissects the open capture.
                if reload then reload_lua_plugins() end
            end
            return true, table.concat(notes, "\n"), buttons, after
        end)
    end)
end

-- Only the protos directory: every subdirectory with .proto files becomes a
-- protocol (FLEET, SHARED, ...) of the dissector; the port map is kept.
local function load_protos()
    local title = "Load protos directory into Wireshark"
    ask_dirs(title, false, nil, function()
        local args = add_common({ "install-dissector", "--plugins-dir", PLUGINS_DIR })
        if config.port_map ~= "" then
            args[#args + 1] = "--port-map"
            args[#args + 1] = config.port_map
        end
        local ok, text = run_backend(args)
        if ok then
            text = json_string(text, "summary") or text
            if reload_lua_plugins then
                show(title, ok, text .. "\n\nReloading Lua plugins...")
                reload_lua_plugins()
                return
            end
            text = text .. "\n\nReload Lua plugins (Analyze > Reload Lua Plugins, Ctrl+Shift+L) to activate."
        end
        show(title, ok, text)
    end)
end

local function about()
    show("nanopb studio", true, table.concat({
        "Plugins folder: " .. PLUGINS_DIR,
        "State file: " .. CONFIG_PATH,
        "nanopb project: " .. project_root() .. (config.nanopb_root ~= "" and " (dev checkout)" or ""),
        "Last input directory: " .. (config.protos_root ~= "" and config.protos_root or "(none)"),
        "Last output directory: " .. (output_dir() ~= "" and output_dir() or "(none)"),
        "Port map: " .. (config.port_map ~= "" and config.port_map or "(none yet)"),
        "Python: " .. config.python,
        "",
        "See tools/wireshark/README.md in the nanopb repository.",
    }, "\n"), nil, { { "Open plugins folder", function() open_folder(PLUGINS_DIR) end } })
end

register_menu("nanopb/Generate C (merged + validation)...", gen_c, MENU_TOOLS_UNSORTED)
register_menu("nanopb/Generate test packets (passed + dropped)...", gen_packets, MENU_TOOLS_UNSORTED)
register_menu("nanopb/Load protos directory into Wireshark...", load_protos, MENU_TOOLS_UNSORTED)
register_menu("nanopb/About", about, MENU_TOOLS_UNSORTED)
