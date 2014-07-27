dofile("init.lua")

recipies = JSON:decode(file_get_contents(config["cookbooks"] .. "/recipies.json"))

log("Execute recipes", LOG_LEVEL_DEBUG)

local attributes = ChefClient.getNodeAttributes()

file_put_contents(config["cookbooks"] .. "/attributes.json", JSON:encode(attributes))

ChefClient.run(recipies, config["cookbooks"])