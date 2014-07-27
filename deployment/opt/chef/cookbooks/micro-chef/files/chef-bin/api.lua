local JSON = (loadfile "json.lua")()
local hasSecHTTP, http = pcall(require, "ssl.https")
if not hasSecHTTP then
	local http = require("socket.http")
end
local ltn12 = require("ltn12")

local ChefClient = { api = {}, cacheData = {}, REQUEST_TRYS = 10, REQUEST_TIMEOUT = 10, REQUEST_CACHE_READ = 1, REQUEST_CACHE_WRITE = 2, REQUEST_CACHE_READ_WRITE = 3 }

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

local child = function(script)
	os.execute("lua " .. script)
end

local isArray = function(t)
    if type(t) ~= "table" then
    	return false
    end
    local count = 0
    for k, v in pairs(t) do
        if type(k) ~= "number" then
        	return false
        else
        	count = count + 1
        end
    end
    for i = 1, count do
		if not t[i] and type(t[i]) ~= "nil" then
			return false
		end
    end
    return true
end

local clone = function(data)
	return JSON:decode(JSON:encode(data))
end

local execute = function(command, input)
	local handle
	if input then
		handle = io.popen("printf '" .. input .. "' | " .. command)
	else
		handle = io.popen(command)
	end
	local result = handle:read("*a")
	handle:close()
	return string.sub(result, 0, string.len(result) - 1)
end

local strSlipt = function(data, bytes)
	local splits = {}
	local line
	repeat
		line = string.sub(data, 0, bytes)
		table.insert(splits, line)
		data = string.sub(data, string.len(line) + 1)
	until string.len(data) == 0
	return splits
end

local hasBinary = function(name)
	local success, state, code = os.execute("which '" .. name .. "' > /dev/null")
	if code == nil then
		code = success
	end
	if code == 0 then
		return true
	else
		return false
	end
end

local download = function(url, target)
	local data = {}

	local handle = io.open(target, "w")

	local page, code, responseHeaders = http.request{
		url = url,
		sink = ltn12.sink.file(handle)
	}

	if handle ~= nil then
		pcall(handle.close)
		pcall(handle.close, handle)
	end

	if code ~= 200 then
		return false
		-- error("HTTP GET returned code other then 200: " .. code)
	end
	return true
end

local md5sum = function(file)
	local data = execute("md5sum '" .. file .. "'")
	return string.match(data, "[a-zA-Z0-9]+")
end

local isFile = function(name)
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

local isDir = function(name)
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

local basename = function(name)
	return execute("basename '" .. name .. "'")
end

local pathname = function(name)
	local bname = basename(name)
	if bname ~= name then
		return string.sub(name, 0, string.len(name) - string.len(bname))
	end
	return nil
end

local mkdir = function(name, path)
	if not isDir(name) then
		if path then
			os.execute("mkdir -p '" .. name .. "'")
		else
			os.execute("mkdir '" .. name .. "'")
		end
	end
end

local rm = function(name)
	if isFile(name) then
		os.execute("rm '" .. name .. "'")
	end
end

-- Helper function which reads the contents of a file(This function is from the helloworld.lua example above)
local fileGetContents = function(filename)
    local file = io.open(filename, "r")
    if not file then
        return nil
    end

    local contents = file:read("*all") -- See Lua manual for more information
    file:close() -- GC takes care of this if you would've forgotten it

    return contents
end

local filePutContents = function(file, data)
  local f = io.open(file, "w")
  f:write(data)
  f:close()
end


function ChefClient.mergeTable(input, override)
	for key, value in pairs(override) do
		if type(value) ~= "table" then
			input[key] = override[key]
		else
			if input[key] == nil or type(input[key]) ~= "table" then
				input[key] = {}
			end
			if isArray(value) then
				for arrayKey, arrayValue in pairs(override[key]) do
					table.insert(input[key], arrayValue)
				end
			else
				ChefClient.mergeTable(input[key], override[key])
			end
		end
	end
end

function ChefClient.OpenSSL_SHA1_Base64(msg)
	return execute("openssl dgst -sha1 -binary | openssl enc -base64", msg)
end

function ChefClient.config(config)
	ChefClient["config"] = config
end

function ChefClient.cache(key, value)
	if value ~= nil then
		ChefClient["cacheData"][key] = value
	end
	return ChefClient["cacheData"][key]
end

function ChefClient.cacheClear()
	ChefClient["cacheData"] = {}
end

function ChefClient.getNodeName()
	return ChefClient["config"]["node"]["name"]
end

function ChefClient.getEnvironment()
	if ChefClient["config"]["environment"] == nil then
		local metadata = ChefClient.api.getNodeMetadata()
		ChefClient["config"]["environment"] = metadata["chef_environment"]
	end
	return ChefClient["config"]["environment"]
end

function ChefClient.setLogger(logger)
	ChefClient["log"] = logger
end

function ChefClient.api.request(url, method, body, cache)
	method = method or "GET"
	body = body or ""

	if type(body) == "table" then
		body = JSON:encode(body)
	end

	if cache == true and (method ~= "GET" or body ~= "") then
		error("Request not cacheable!")
	end

	local cacheKey = "request:" .. method .. ":" .. url
	local cacheData
	if cache == true or cache == ChefClient.REQUEST_CACHE_READ or cache == ChefClient.REQUEST_CACHE_READ_WRITE then
		cacheData = ChefClient.cache(cacheKey)
		if cacheData ~= nil then
			ChefClient.log("Request (From cache) " .. method .. " " .. url .. " " .. body)
			return cacheData
		end
	end

	local endpoint = url
	local clientCertificate = ChefClient["config"]["client"]["key"]
	local path = ChefClient["config"]["server"] .. url
	local clientName = ChefClient["config"]["client"]["name"]
	local timestamp = os.date("%Y-%m-%dT%H:%M:%SZ")
	local hashedPath = ChefClient.OpenSSL_SHA1_Base64(endpoint)
	local hashedBody = ChefClient.OpenSSL_SHA1_Base64(body)

	local canonicalRequest = "Method:" .. method .. "\nHashed Path:" .. hashedPath .. "\nX-Ops-Content-Hash:" .. hashedBody .. "\nX-Ops-Timestamp:" .. timestamp .. "\nX-Ops-UserId:" .. clientName
	local headers = {}

	headers["X-Ops-Timestamp"] = timestamp
	headers["X-Ops-Userid"] = clientName
	headers["X-Chef-Version"] = "0.10.4"
	headers["Accept"] = "application/json"
	headers["X-Ops-Content-Hash"] = hashedBody
	headers["X-Ops-Sign"] = "version=1.0"
	headers["Content-Length"] = string.len(body)

	local authHeadersData = string.gsub(execute("openssl rsautl -sign -inkey " .. clientCertificate .. " | openssl enc -base64", canonicalRequest), "\n", "")
	local authHeadersDataSplitted = strSlipt(authHeadersData, 60)
	local authHeaders = ""

	local curlString = "curl -i -X " .. method

	for ip, str in pairs(authHeadersDataSplitted) do
		headers["X-Ops-Authorization-" .. ip] = str
	end

	for key, value in pairs(headers) do
		curlString = curlString .. " -H '" .. key .. ":" .. value .. "'"
	end

	if body ~= "" then
		curlString = curlString .. " -d '" .. body .. "'"
	end
	curlString = curlString .. " '" .. path .. "'"
	


	local data = {}
	local page, code, responseHeaders

	trys = 1
	repeat
		if trys > ChefClient.REQUEST_TRYS then
			error("Could not request " .. method .. " " .. endpoint .. "!")
		end
		-- print(dump(curlString))
		ChefClient.log("Request (Try " .. trys .. "/" .. ChefClient.REQUEST_TRYS .. ") " .. method .. " " .. endpoint .. " " .. body)

		local oldTimeout = TIMEOUT
		TIMEOUT = ChefClient.REQUEST_TIMEOUT

		page, code, responseHeaders = http.request{
			url = path,
			method = method,
			source = ltn12.source.string(body),
			headers = headers,
			sink = ltn12.sink.table(data)
		}
		trys = trys + 1

		TIMEOUT = oldTimeout
	until type(code) == "number"

	local content = table.concat(data, "")

	if code ~= 200 then
		error("chef returned code other then 200: " .. code .. " " .. content)
	end

	cacheData = JSON:decode(content)

	if cache == true or cache == ChefClient.REQUEST_CACHE_WRITE or cache == ChefClient.REQUEST_CACHE_READ_WRITE then
		ChefClient.cache(cacheKey, cacheData)
	end

	return cacheData
end

function ChefClient.syncCookbook(cookbook, target)
	ChefClient.log("Sync cookbook '" .. cookbook["name"] .. "' to '" .. target .. "'.")
	local versionFile = target .. "/.version"
	local mapFile = target .. "/.filemap"
	if isFile(versionFile) then
		local cookbookSyncedVersion = fileGetContents(versionFile)
		if cookbookSyncedVersion == cookbook["version"] then
			ChefClient.log("Cookbook '" .. cookbook["name"] .. "' is already in sync.")
			return false
		else
			ChefClient.log("Cookbook '" .. cookbook["name"] .. "' is outdated. Version '" .. cookbookSyncedVersion .. "' is present in filesystem.")
		end
	end

	local types = {"resources", "recipes", "definitions", "attributes", "files", "templates", "root_files"}
	local targetFile
	local targetFileShort
	local targetPath
	local typePathShort
	local typePath
	local trys
	local downloadSucess
	local newMap = {}
	local removeMap = {}
	local typePathCreated

	if isFile(mapFile) then
		removeMap = JSON:decode(fileGetContents(mapFile))
	end

	for i, ctype in pairs(types) do
		typePathCreated = false
		if ctype ~= "root_files" then
			typePathShort = ctype
			typePath = target .. "/" .. ctype
		else
			typePathShort = ''
			typePath = target
		end
		for key, data in pairs(cookbook[ctype]) do
			if not typePathCreated then
				mkdir(typePath)
			end
			targetFileShort = typePathShort .. "/" .. data["name"]
			targetFile = typePath .. "/" .. data["name"]
			if removeMap[targetFileShort] ~= nil then
				removeMap[targetFileShort] = nil
			end
			newMap[targetFileShort] = true
			-- do not download files that exist and have not beeing modified
			if isFile(targetFile) and md5sum(targetFile) == data["checksum"] then
				ChefClient.log("Skip downloading of '" .. ctype .. " " .. data["name"] .. "' because checksum equals checksum of file in file system.")
			else
				trys = 1
				-- try to download the file until the checksum matches
				repeat
					if trys > ChefClient.REQUEST_TRYS then
						error("Could not download file '" .. targetFile .. "'! Checksum mismatch " .. ChefClient.REQUEST_TRYS .. " times.")
					end
					ChefClient.log("Download '" .. data["url"] .. "' to '" .. targetFile .. "'")
					targetPath = pathname(targetFile)
					if targetPath ~= nil then
						mkdir(targetPath, true)
					end
					downloadSucess = download(data["url"], targetFile)
					trys = trys + 1
				until downloadSucess and md5sum(targetFile) == data["checksum"]
			end
		end
	end

	for removeFile, removed in pairs(removeMap) do
		if removed then
			ChefClient.log("Remove file '" .. target .. removeFile .. "'.")
			rm(target .. removeFile)
		end
	end

	ChefClient.log("Create version file '" .. cookbook["version"] .. "'.")
	filePutContents(versionFile, cookbook["version"])
	filePutContents(mapFile, JSON:encode(newMap))
	ChefClient.log("Cookbook '" .. cookbook["name"] .. "' is now in sync.")
	return true
end

function ChefClient.extractCookbooksFromRecipes(recipes)
	local cookbookDupes = {}
	local cookbooks = {}
	local cookbookName
	for key, recipe in pairs(recipes) do
		if type(recipe) == "table" then
			cookbookName = recipe["cookbook"]
		else
			cookbookName = string.match(recipe, "^(.+)::")
			if cookbookName == nil then
				cookbookName = recipe
			end
		end
		if cookbookDupes[cookbookName] == nil then
			table.insert(cookbooks, cookbookName)
		end
		cookbookDupes[cookbookName] = true
	end
	return cookbooks
end

function ChefClient.parseRunList(list)
	local runList = {}
	local type
	local argument
	local opt

	for key, item in pairs(list) do
		itemTypes = string.match(item, "^(.+)[(.+)]")

		type, argument, opt = string.match(item, '^(.*)%[(.+)::(.+)%]$')
		if type == nil then
			type, argument = string.match(item, '^(.*)%[(.+)%]$')
		end

		local parsedItem = {}
		parsedItem["type"] = type
		parsedItem["argument"] = argument
		parsedItem["option"] = opt
		table.insert(runList, parsedItem)
	end
	return runList
end

function ChefClient.syncCookbooks(cookbooks, target)
	if not isDir(target) then
		error("Target directory '" .. target .. "' does not exist.")
	end

	local cookbookTarget
	local cookbookMetadata

	for cookbook, version in pairs(cookbooks) do
		if type(cookbook) == "number" then
			cookbook = version
			version = nil
		end
		if version ~= nil then
			cookbookMetadata = ChefClient.api.getCookbookVersion(cookbook, version)
		else
			cookbookMetadata = ChefClient.api.getLatestCookbookVersion(cookbook)
		end
		cookbookTarget = target .. "/" .. cookbook
		mkdir(cookbookTarget)
		ChefClient.syncCookbook(cookbookMetadata, cookbookTarget)
	end
end

function ChefClient.getRoleRunList(name, environment, newRunList, roles)
	if environment == nil then
		environment = ChefClient.getEnvironment()
	end
	local role = ChefClient.api.getRole(name)
	local runList

	if role["env_run_lists"][environment] ~= nil then
		runList = role["env_run_lists"][environment]
	else
		runList = role["run_list"]
	end

	runList = ChefClient.parseRunList(runList)

	if newRunList == nil then
		newRunList = {}
	end
	if roles == nil then
		roles = {}
	end

	for key, item in pairs(runList) do
		if item["type"] == "role" then
			if roles[item["argument"]] == nil then
				table.insert(newRunList, item)
				roles[item["argument"]] = true
				newRunList = ChefClient.getRoleRunList(item["argument"], environment, newRunList, roles)
			end
		else
			table.insert(newRunList, item)
		end
	end

	return newRunList
end

function ChefClient.getRunList(nodeName, environment)
	local node = ChefClient.api.getNodeMetadata(nodeName)
	if environment == nil then
		environment = ChefClient.getEnvironment()
	end
	local runList = ChefClient.parseRunList(node["run_list"])
	local roleDupes = {}
	local roles = {}
	local cookbooks = {}
	local recipesDupes = {}
	local recipes = {}
	local newRunList = {}
	local recipeOption
	local recipe

	for key, item in pairs(runList) do
		if item["type"] == "role" then
			if roleDupes[item["argument"]] == nil then
				table.insert(newRunList, item)
				roleDupes[item["argument"]] = true
				newRunList = ChefClient.getRoleRunList(item["argument"], environment, newRunList, roleDupes)
			end
		else
			table.insert(newRunList, item)
		end
	end

	for key, item in pairs(newRunList) do
		if item["type"] == "recipe" then
			recipeOption = item["option"]
			if recipeOption == nil then
				recipeOption = "default"
			end
			recipe = {}
			recipe["name"] = item["argument"]
			if item["option"] ~= nil then
				recipe["name"] = recipe["name"] .. "::" .. item["option"]
			end
			recipe["cookbook"] = item["argument"]
			recipe["recipe"] = recipeOption
			if recipesDupes[recipe["name"]] == nil then
				recipesDupes[recipe["name"]] = true
				table.insert(recipes, recipe)
			end
		elseif item["type"] == "role" then
			table.insert(roles, item["argument"])
		end
	end

	cookbooks = ChefClient.extractCookbooksFromRecipes(recipes)

	return newRunList, recipes, cookbooks, roles 
end

function ChefClient.selectCookbookVersion(cookbookVersions, version)
	-- todo
	return cookbookVersions[1]["version"]
end

function ChefClient.getCookbookVersions(cookbooks, environment, dependencies)
	environment = environment or ChefClient.getEnvironment()
	dependencies = dependencies or {}
	local cookbookMetadata
	local cookbookVersion
	local cookbookVersion
	local cookbookSelectedVersion

	for name, version in pairs(cookbooks) do
		if type(name) == "number" then
			name = version
			version = nil
		end
		if dependencies[name] == nil then
			cookbookMetadata = ChefClient.api.getCookbookMetadataForEnvironment(name, environment)
			cookbookSelectedVersion = cookbookMetadata["versions"][1]["version"]
			if version ~= nil then
				cookbookSelectedVersion = ChefClient.selectCookbookVersion(cookbookMetadata["versions"], version)
			end
			cookbookVersion  = ChefClient.api.getCookbookVersion(name, cookbookSelectedVersion, ChefClient.REQUEST_CACHE_READ_WRITE)
			dependencies[name] = cookbookVersion["version"]
			ChefClient.getCookbookVersions(cookbookVersion["metadata"]["dependencies"], environment, dependencies)
		end
	end

	return dependencies
end


function ChefClient.getNodeAttributes(nodeName, environmentName)
	local node = ChefClient.api.getNodeMetadata(nodeName)
	environmentName = environmentName or node["chef_environment"]
	local environment = ChefClient.api.getEnvironment(environmentName)

	local runList, recipes, cookbooks, roles = ChefClient.getRunList(nodeName, environmentName)

	local automaticAttributes = {}

	local override = {}
	local default = {}
	local normal = clone(node["normal"])
	local automatic = {}
	local result = {}

	ChefClient.mergeTable(default, environment["default_attributes"])
	for key, role in pairs(roles) do
		local role = ChefClient.api.getRole(role)
		ChefClient.mergeTable(default, role["default_attributes"])
	end

	ChefClient.mergeTable(override, environment["override_attributes"])
	for key, role in pairs(roles) do
		local role = ChefClient.api.getRole(role)
		ChefClient.mergeTable(override, role["override_attributes"])
	end


	ChefClient.mergeTable(result, default)
	ChefClient.mergeTable(result, normal)
	ChefClient.mergeTable(result, override)
	ChefClient.mergeTable(result, automatic)

	return result, automatic, normal, default, override
end

function ChefClient.executeLuaRecipe(path)
	ChefClient.log("Execute " .. path)
	child("'" .. path  .. "' '" .. "/etc/chef/config.json" .. "'")
end

function ChefClient.executeShellRecipe(path)
	ChefClient.log("Execute " .. path)
	os.execute("'" .. path  .. "' '" .. "/etc/chef/config.json" .. "'")
end

function ChefClient.runSingle(item, dir)
	local path = dir .. "/" .. item["cookbook"] .. "/recipes/" .. item["recipe"];
	
	if isFile(path .. ".lua") then
		ChefClient.executeLuaRecipe(path .. ".lua")
	elseif isFile(path .. ".sh") then
		ChefClient.executeShellRecipe(path .. ".sh")
	end
end

function ChefClient.run(runList, dir)
	for _, item in pairs(runList) do
		ChefClient.runSingle(item, dir)
	end
end

function ChefClient.api.getCookbookMetadata(name, cache)
	cache = cache or ChefClient.REQUEST_CACHE_READ
	local data = ChefClient.api.request("/cookbooks/" .. name, nil, nil, cache)
	return data[name]
end

function ChefClient.api.getCookbookMetadataForEnvironment(name, environment, cache)
	cache = cache or ChefClient.REQUEST_CACHE_READ
	environment = environment or ChefClient.getEnvironment()
	local data = ChefClient.api.request("/environments/" .. environment .. "/cookbooks/" .. name, nil, nil, cache)
	return data[name]
end

function ChefClient.api.getLatestCookbookVersionMetadata(name)
	local cookbook = ChefClient.api.getCookbookMetadata(name)
	return cookbook["versions"][1]
end

function ChefClient.api.getCookbookVersion(name, version, cache)
	cache = cache or ChefClient.REQUEST_CACHE_READ
	return ChefClient.api.request("/cookbooks/" .. name .. "/" .. version, nil, nil, cache)
end

function ChefClient.api.getLatestCookbookVersion(name)
	local cookbook = ChefClient.api.getLatestCookbookVersionMetadata(name)
	return ChefClient.api.getCookbookVersion(name, cookbook["version"])
end

function ChefClient.api.getNodeMetadata(name, cache)
	cache = cache or ChefClient.REQUEST_CACHE_READ_WRITE
	if name == nil then
		name = ChefClient.getNodeName()
	end
	local data = ChefClient.api.request("/nodes/" .. name, nil, nil, cache)
	return data
end

function ChefClient.api.getRole(name, cache)
	cache = cache or ChefClient.REQUEST_CACHE_READ_WRITE
	local data = ChefClient.api.request("/roles/" .. name, nil, nil, cache)
	return data
end

function ChefClient.api.getEnvironment(name, cache)
	cache = cache or ChefClient.REQUEST_CACHE_READ_WRITE
	if name == nil then
		name = ChefClient.getEnvironment()
	end
	local data = ChefClient.api.request("/environments/" .. name, nil, nil, cache)
	return data
end

return ChefClient