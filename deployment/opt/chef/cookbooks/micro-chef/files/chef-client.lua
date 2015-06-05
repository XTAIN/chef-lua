
function child(script)
	os.execute("lua '" .. script .. "'")
end

dofile("init.lua")

local data = {
  automatic = ChefClient.ohai.get()
}

ChefClient.api.saveNode(data)

child("manage.lua")
child("run.lua")
