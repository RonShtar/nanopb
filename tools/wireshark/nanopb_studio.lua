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
            "From the nanopb checkout run\n\n" ..
            "    python tools/wireshark/backend/nanopb_wireshark.py install-studio\n\n" ..
            "and reload Lua plugins (Ctrl+Shift+L)."
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

local function show(title, ok, text, folder)
    local win = TextWindow.new(title)
    win:set((ok and "OK\n\n" or "FAILED\n\n") .. text)
    if ok and folder then
        win:add_button("Open output folder", function() open_folder(folder) end)
    end
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
    return names
end

-- Show the units of the input directory as a toggle list. `generate` gets the
-- comma separated selection and returns ok, output text.
local function pick_units(title, generate)
    local ok, text = run_backend(add_common({ "units", "--names-only" }))
    if not ok then
        show(title, false, text)
        return
    end
    local names = parse_unit_names(text)
    if #names == 0 then
        show(title, false, "No subdirectory of " .. config.protos_root .. " contains .proto files.")
        return
    end
    local selected = {}
    for _, name in ipairs(names) do selected[name] = true end

    local win = TextWindow.new(title .. ": choose units")
    local function render(note)
        local lines = {
            "Click a unit to select or deselect it, then press Generate.",
            "",
            "Input:  " .. config.protos_root,
            "Output: " .. output_dir(),
            "",
        }
        for _, name in ipairs(names) do
            lines[#lines + 1] = (selected[name] and "  [x] " or "  [ ] ") .. name
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
        local done, out = generate(table.concat(chosen, ","))
        render(done and ("Generated: " .. table.concat(chosen, ", ")) or "FAILED, see the result window.")
        show(title, done, out, output_dir())
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
            return run_backend(args)
        end)
    end)
end

local function gen_data(invalid)
    local title = invalid and "Generate invalid raw data" or "Generate raw data"
    ask_dirs(title, true, nil, function()
        pick_units(title, function(units)
            local args = add_common({ "gen-data", "--out", output_dir(), "--unit", units })
            if invalid then args[#args + 1] = "--invalid" end
            return run_backend(args)
        end)
    end)
end

local function install_dissector()
    ask_dirs("Install / update dissector", false, {
        { "Port map (e.g. udp:5000=pkg.Envelope,tcp:7000=pkg.Cmd)", config.port_map },
    }, function(port_map)
        config.port_map = trim(port_map)
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

local function list_units()
    ask_dirs("List proto units", false, nil, function()
        local ok, text = run_backend(add_common({ "units" }))
        show("nanopb units", ok, text)
    end)
end

local function about()
    show("nanopb studio", true, table.concat({
        "Plugins folder: " .. PLUGINS_DIR,
        "State file: " .. CONFIG_PATH,
        "nanopb project: " .. (config.nanopb_root ~= "" and config.nanopb_root or "(not set, run install-studio)"),
        "Last input directory: " .. (config.protos_root ~= "" and config.protos_root or "(none)"),
        "Last output directory: " .. (output_dir() ~= "" and output_dir() or "(none)"),
        "Python: " .. config.python,
        "",
        "See tools/wireshark/README.md in the nanopb repository.",
    }, "\n"))
end

register_menu("nanopb/Generate C (merged + validation)...", gen_c, MENU_TOOLS_UNSORTED)
register_menu("nanopb/Generate raw data...", function() gen_data(false) end, MENU_TOOLS_UNSORTED)
register_menu("nanopb/Generate invalid raw data...", function() gen_data(true) end, MENU_TOOLS_UNSORTED)
register_menu("nanopb/Install or update dissector...", install_dissector, MENU_TOOLS_UNSORTED)
register_menu("nanopb/List proto units...", list_units, MENU_TOOLS_UNSORTED)
register_menu("nanopb/About", about, MENU_TOOLS_UNSORTED)
