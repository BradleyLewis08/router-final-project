def test_ping_all_router_interfaces(hosts, routers, interfaces):
	for host in hosts:
		for router in routers:
			for interface in interfaces[router.name]:
				print(f"Pinging {interface['ip']} from {host.name}")
				print(host.cmd(f"ping -c1 {interface['ip']}"))




	
