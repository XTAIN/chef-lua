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

-- log(dump(config), LOG_LEVEL_DEBUG)

ChefClient.config(config["chef"])
ChefClient.setLogger(log)