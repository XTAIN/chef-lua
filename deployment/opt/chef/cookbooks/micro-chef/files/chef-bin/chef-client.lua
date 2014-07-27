
function child(script)
	os.execute("lua '" .. script .. "'")
end

child("manage.lua")
child("run.lua")
