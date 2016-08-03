package = "coroner"
version = "1.0-1"

source = {
	url = "git://github.com/antagon/coroner",
	tag = "1.0"
}

description = {
	summary = "A packet dissection framework.",
	homepage = "http://codeward.org/software/coroner",
	maintainer = "Dan Antagon <antagon@codeward.org>",
	license = "MIT"
}

dependencies = {
	"lua >= 5.2"
}

build = {
	type = "builtin",
	modules = {
		eth = "src/protocol/eth.lua",
		icmp = "src/protocol/icmp.lua",
		ip = "src/protocol/ip.lua",
		ipv6 = "src/protocol/ipv6.lua",
		tcp = "src/protocol/tcp.lua",
		udp = "src/protocol/udp.lua"
	}
}

