
function child(script)
	os.execute("lua '" .. script .. "'")
end

dofile("init.lua")

local data = {
  automatic = ChefClient.ohai.get()
}

writeAttributes(data)

child("manage.lua")
child("run.lua")
