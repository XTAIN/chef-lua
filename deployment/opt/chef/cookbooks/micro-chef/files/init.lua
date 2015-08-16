JSON = (loadfile "json.lua")()
ChefClient = require "api"

-- works like PHP's print_r(), returning the output instead of printing it to STDOUT
-- daniel speakmedia com

function dump(data)
    -- cache of tables already printed, to avoid infinite recursive loops
    local tablecache = {}
    local buffer = ""
    local padder = "    "

    local function _dump(d, depth)
        local t = type(d)
        local str = tostring(d)
        if (t == "table") then
            if (tablecache[str]) then
                -- table already dumped before, so we dont
                -- dump it again, just mention it
                buffer = buffer.."<"..str..">\n"
            else
                tablecache[str] = (tablecache[str] or 0) + 1
                buffer = buffer.."("..str..") {\n"
                for k, v in pairs(d) do
                    buffer = buffer..string.rep(padder, depth+1).."["..k.."] => "
                    _dump(v, depth+1)
                end
                buffer = buffer..string.rep(padder, depth).."}\n"
            end
        elseif (t == "number") then
            buffer = buffer.."("..t..") "..str.."\n"
        else
            buffer = buffer.."("..t..") \""..str.."\"\n"
        end
    end
    _dump(data, 0)
    return buffer
end

function execute(command, input)
    local handle
    if input then
        handle = io.popen("echo -n '" .. input .. "' | " .. command)
    else
        handle = io.popen(command)
    end
    local result = handle:read("*a")
    handle:close()
    return string.sub(result, 0, string.len(result) - 1)
end

function clone(data)
    return JSON:decode(JSON:encode(data))
end

function tableGetKeyByValue(t, value)
    for k,v in pairs(t) do
        if v == value then
            return k
        end
    end

    return nil
end

function tableRemoveByValue(t, value)
    table.remove(t, tableGetKeyByValue(t, value))
end

function rm(name)
    if isFile(name) then
        os.execute("rm '" .. name .. "'")
    end
end

function scandir(directory)
    local i, t, popen = 0, {}, io.popen
    for filename in popen('ls "'..directory..'"'):lines() do
        i = i + 1
        t[i] = filename
    end
    return t
end

function trim(s)
    return (s:gsub("^%s*(.-)%s*$", "%1"))
end

-- Helper function which reads the contents of a file(This function is from the helloworld.lua example above)
function file_get_contents(filename)
    local file = io.open(filename, "r")
    if not file then
        return nil
    end

    local contents = file:read("*all") -- See Lua manual for more information
    file:close() -- GC takes care of this if you would've forgotten it

    return contents
end

function file_put_contents(file, data)
  local f = io.open(file, "w")
  f:write(data)
  f:close()
end

function execute(command, input)
    local handle
    if input then
        handle = io.popen("echo -n '" .. input .. "' | " .. command)
    else
        handle = io.popen(command)
    end
    local result = handle:read("*a")
    handle:close()
    return string.sub(result, 0, string.len(result) - 1)
end

function stat(option, file)
    return execute("/usr/bin/stat -c %" .. option .. " '" .. file .. "'")
end

function isDir(name)
    local success, state, code = os.execute("[ -d '" .. name .. "' ]")
    if code == nil then
        code = success
    end
    if code == 0 then
        return true
    else
        return false
    end
end

function isFile(name)
    local success, state, code = os.execute("[ -f '" .. name .. "' ]")
    if code == nil then
        code = success
    end
    if code == 0 then
        return true
    else
        return false
    end
end

function file_ensure(file, content, owner, group, mode)
    local changed = false

    if not isFile(file) or content ~= file_get_contents(file) then
        print(" => Install new file: " .. file)
        file_put_contents(file, content)
        changed = true
    end

    if owner ~= nil and owner ~= stat("U", file) then
        os.execute("chown '" .. owner .. "' '" .. file .. "'")
        changed = true
    end

    if group ~= nil and group ~= stat("G", file) then
        os.execute("chgrp '" .. group .. "' '" .. file .. "'")
        changed = true
    end

    if mode ~= nil and mode ~= tonumber(stat("a", file), 8) then
        os.execute("chmod '" .. string.format("%o", mode) .. "' '" .. file .. "'")
        changed = true
    end

    return changed
end

function dir_ensure(dir, owner, group, mode)
    local changed = false

    if not isDir(dir) then
        os.execute("mkdir '" .. dir .. "'")
    end

    if owner ~= nil and owner ~= stat("U", dir) then
        os.execute("chown '" .. owner .. "' '" .. file .. "'")
        changed = true
    end

    if group ~= nil and group ~= stat("G", dir) then
        os.execute("chgrp '" .. group .. "' '" .. file .. "'")
        changed = true
    end

    if mode ~= nil and mode ~= tonumber(stat("a", dir), 8) then
        os.execute("chmod '" .. string.format("%o", mode) .. "' '" .. dir .. "'")
        changed = true
    end

    return changed
end

function sleep(n)
  os.execute("sleep " .. tonumber(n))
end

LOG_LEVEL_DEBUG = "LOG_LEVEL_DEBUG"

function log(msg, level)
	print(msg)
end


configData = file_get_contents("config.json")
if configData == nil then
    configData = file_get_contents("/etc/chef/config.json")
end

config = JSON:decode(configData)

function writeAttributes(attributes)
    if attributes == nil then
        attributes = {}
    end
    if attributes['attributes'] == nil then
        attributes['attributes'] = ChefClient.getNodeAttributes()
    end
    if attributes['normal'] == nil then
        attributes['normal'] = {}
    end
    file_put_contents(config["cookbooks"] .. "/attributes.json", JSON:encode(attributes))
end

function readAttributes()
    local attributes = JSON:decode(file_get_contents(config["cookbooks"] .. "/attributes.json"))
    if attributes == nil then
        attributes = {}
    end
    if attributes['attributes'] == nil then
        attributes['attributes'] = ChefClient.getNodeAttributes()
    end
    if attributes['normal'] == nil then
        attributes['normal'] = {}
    end
    return attributes
end

function interpolate(s, tab)
  return (s:gsub('($%b{})', function(w) return tab[w:sub(3, -2)] or w end))
end

-- log(dump(config), LOG_LEVEL_DEBUG)

ChefClient.config(config["chef"])
ChefClient.setLogger(log)
