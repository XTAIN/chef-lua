
function child(script)
	os.execute("lua '" .. script .. "'")
end

dofile("init.lua")

child("manage.lua")
child("run.lua")

local data = {
  automatic = ChefClient.ohai.get()
}

ChefClient.api.saveNode(data)
