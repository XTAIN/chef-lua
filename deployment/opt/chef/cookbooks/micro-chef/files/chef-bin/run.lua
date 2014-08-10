dofile("init.lua")

recipies = JSON:decode(file_get_contents(config["cookbooks"] .. "/recipies.json"))

log("Execute recipes", LOG_LEVEL_DEBUG)

writeAttributes()

ChefClient.run(recipies, config["cookbooks"])