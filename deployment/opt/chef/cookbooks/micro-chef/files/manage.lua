dofile("init.lua")

log("Get run list", LOG_LEVEL_DEBUG)

local runList, recipes, cookbooks, roles = ChefClient.getRunList()

log("Find dependencies", LOG_LEVEL_DEBUG)

local dependencies = ChefClient.getCookbookVersions(cookbooks)

-- log(dump(dependencies))

log("Sync cookbooks", LOG_LEVEL_DEBUG)

ChefClient.syncCookbooks(dependencies, config["cookbooks"])

file_put_contents(config["cookbooks"] .. "/recipies.json", JSON:encode(recipes))
