package = "capdiss_protocols"
version = "0.0.1-1"

source = {
	url = "git://github.com/antagon/capdiss_protocols",
	tag = "0.0.1"
}

description = {
	summary = "Protocol dissectors for capdiss.",
	homepage = "http://codeward.org/software/capdiss",
	license = "MIT"
}

dependencies = {
	"lua >= 5.1"
}

build = {
	type = "builtin",
	modules = {
		eth = "src/eth.lua",
		ip = "src/ip.lua",
		tcp = "src/tcp.lua"
	}
}

