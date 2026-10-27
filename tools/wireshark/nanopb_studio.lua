-- nanopb_studio.lua
--
-- Tools > nanopb menu for Wireshark: generate merged nanopb C code (with
-- validation) and encoded sample data from a directory of .proto units, and
-- install/update nanopb_any_dissector.lua with a matching schema.
--
-- All work is done by tools/wireshark/backend/nanopb_wireshark.py in the
-- configured nanopb checkout; this file only collects input and shows output.
-- Settings are stored in nanopb/studio_config.luadata next to this file.
--
-- Works with Wireshark 3.6+ (Lua 5.2 - 5.4) on Windows and Linux.

if not gui_enabled() then return end

if set_plugin_info then
    set_plugin_info({
        version = "1.0.0",
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
-- Settings
-- ---------------------------------------------------------------------------

local KEYS = { "python", "nanopb_root", "protos_root", "output_dir", "extra_includes", "port_map" }

local config = {
    python = IS_WINDOWS and "python" or "python3",
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
    f:write("-- nanopb studio settings (edit via Tools > nanopb > Settings)\nreturn {\n")
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

local function backend_path()
    return join(config.nanopb_root, "tools", "wireshark", "backend", "nanopb_wireshark.py")
end

local function file_exists(path)
    local f = io.open(path, "r")
    if f then f:close() return true end
    return false
end

-- Run the backend with a list of arguments. Returns ok, output text.
local function run_backend(args)
    if config.nanopb_root == "" or not file_exists(backend_path()) then
        return false, "nanopb project path is not set or has no tools/wireshark/backend.\n" ..
            "Open Tools > nanopb > Settings."
    end
    local parts = { quote(config.python), quote(backend_path()), "--nanopb-root", quote(config.nanopb_root) }
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
        return false, "Backend did not run. Check the Python path in Settings.\n\n" .. cmd .. "\n\n" .. out
    end
    return status == "0", out
end

local function add_common(args)
    args[#args + 1] = "--protos-root"
    args[#args + 1] = config.protos_root
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

local function show(title, ok, text, folder)
    local win = TextWindow.new(title)
    win:set((ok and "OK\n\n" or "FAILED\n\n") .. text)
    if ok and folder then
        win:add_button("Open output folder", function() open_folder(folder) end)
    end
end

local function require_protos()
    if config.protos_root == "" then
        show("nanopb", false, "Set the protos directory first (Tools > nanopb > Settings).")
        return false
    end
    return true
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

local function yes(value)
    value = (value or ""):lower()
    return value == "y" or value == "yes" or value == "1" or value == "true"
end

-- ---------------------------------------------------------------------------
-- Menu actions
-- ---------------------------------------------------------------------------

local function settings()
    dialog("nanopb settings", {
        { "nanopb project path (checkout with generator/)", config.nanopb_root },
        { "Protos directory (one subdirectory per unit)", config.protos_root },
        { "Output directory (empty = <protos>/../nanopb_out)", config.output_dir },
        { "Extra proto include dirs (; separated)", config.extra_includes },
        { "Python executable", config.python },
    }, function(root, protos, out, includes, python)
        config.nanopb_root = root or ""
        config.protos_root = protos or ""
        config.output_dir = out or ""
        config.extra_includes = includes or ""
        if python and python ~= "" then config.python = python end
        local saved, err = save_config()
        local notes = {}
        if not saved then notes[#notes + 1] = "Could not save settings: " .. tostring(err) end
        if not file_exists(backend_path()) then
            notes[#notes + 1] = "Warning: " .. backend_path() .. " not found."
        end
        local ok, text = run_backend(add_common({ "units" }))
        notes[#notes + 1] = text
        show("nanopb settings", saved and ok, table.concat(notes, "\n\n"))
    end)
end

local function list_units()
    if not require_protos() then return end
    local ok, text = run_backend(add_common({ "units" }))
    show("nanopb units", ok, text)
end

local function gen_c()
    if not require_protos() then return end
    dialog("Generate C (merged, with validation)", {
        { "Units (comma separated, empty = all)", "" },
        { "Copy nanopb runtime sources (y/n)", "y" },
        { "Validation code (y/n)", "y" },
    }, function(units, runtime, validate)
        local args = add_common({ "gen-c", "--out", output_dir() })
        if units and units ~= "" then args[#args + 1] = "--unit"; args[#args + 1] = units end
        if yes(runtime) then args[#args + 1] = "--with-runtime" end
        if not yes(validate) then args[#args + 1] = "--no-validate" end
        local ok, text = run_backend(args)
        show("nanopb: generate C", ok, text, output_dir())
    end)
end

local function gen_data()
    if not require_protos() then return end
    dialog("Generate raw data", {
        { "Units (comma separated, empty = all)", "" },
        { "Messages (comma separated, empty = all)", "" },
        { "Formats (bin,c,hex)", "bin,c,hex" },
        { "Samples per message", "1" },
        { "Seed (empty = random)", "" },
        { "Invalid data (y/n)", "n" },
        { "Invalid: fields to violate (comma separated)", "" },
        { "Invalid: rules to violate (comma separated)", "" },
    }, function(units, messages, formats, count, seed, invalid, vfields, vrules)
        local args = add_common({ "gen-data", "--out", output_dir() })
        local function opt(flag, value)
            if value and value ~= "" then args[#args + 1] = flag; args[#args + 1] = value end
        end
        opt("--unit", units)
        opt("--messages", messages)
        opt("--formats", formats)
        opt("--count", count)
        opt("--seed", seed)
        if yes(invalid) then
            args[#args + 1] = "--invalid"
            for f in string.gmatch(vfields or "", "[^,%s]+") do opt("--field", f) end
            for r in string.gmatch(vrules or "", "[^,%s]+") do opt("--rule", r) end
        end
        local ok, text = run_backend(args)
        show("nanopb: generate raw data", ok, text, output_dir())
    end)
end

local function install_dissector()
    if not require_protos() then return end
    dialog("Install / update dissector", {
        { "Port map (e.g. udp:5000=pkg.Envelope,tcp:7000=pkg.Cmd)", config.port_map },
    }, function(port_map)
        config.port_map = port_map or ""
        save_config()
        local args = add_common({ "install-dissector", "--plugins-dir", PLUGINS_DIR,
            "--port-map", config.port_map })
        local ok, text = run_backend(args)
        if ok then
            if reload_lua_plugins then
                text = text .. "\n\nReloading Lua plugins..."
                show("nanopb: install dissector", ok, text)
                reload_lua_plugins()
                return
            end
            text = text .. "\n\nReload Lua plugins (Analyze > Reload Lua Plugins, Ctrl+Shift+L) to activate."
        end
        show("nanopb: install dissector", ok, text)
    end)
end

local function about()
    show("nanopb studio", true, table.concat({
        "Plugins folder: " .. PLUGINS_DIR,
        "Settings file: " .. CONFIG_PATH,
        "nanopb project: " .. (config.nanopb_root ~= "" and config.nanopb_root or "(not set)"),
        "Protos directory: " .. (config.protos_root ~= "" and config.protos_root or "(not set)"),
        "Output directory: " .. (output_dir() ~= "" and output_dir() or "(not set)"),
        "Python: " .. config.python,
        "",
        "See tools/wireshark/README.md in the nanopb repository.",
    }, "\n"))
end

register_menu("nanopb/Settings...", settings, MENU_TOOLS_UNSORTED)
register_menu("nanopb/List proto units", list_units, MENU_TOOLS_UNSORTED)
register_menu("nanopb/Generate C (merged + validation)...", gen_c, MENU_TOOLS_UNSORTED)
register_menu("nanopb/Generate raw data...", gen_data, MENU_TOOLS_UNSORTED)
register_menu("nanopb/Install or update dissector...", install_dissector, MENU_TOOLS_UNSORTED)
register_menu("nanopb/About", about, MENU_TOOLS_UNSORTED)
