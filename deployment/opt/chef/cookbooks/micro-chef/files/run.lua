dofile("init.lua")

recipies = JSON:decode(file_get_contents(config["cookbooks"] .. "/recipies.json"))

log("Execute recipes", LOG_LEVEL_DEBUG)

ChefClient.run(recipies, config["cookbooks"])

local attributes = readAttributes()

attributes['automatic'] = ChefClient.ohai.get()
attributes['attributes'] = nil

ChefClient.api.saveNode(attributes)
