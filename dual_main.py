import sys
import time
sys.path.append("/home/bradleylewis/p4app/docker/scripts")
sys.path.append("/home/bradleylewis/p4-build/p4dev-python-venv/lib/python3.10/site-packages")
from tests import test_ping_all_router_interfaces

HOST_SWITCH_INGRESS_PORT = 4

from p4app import P4Mininet

from controller import Controller
from my_topo import DualSwitchTopo

# ----------------- INITIALIZATION FUNCTIONS -----------------

def init_multicast(switches):
	bcast_mgid = 1
	for switch in switches:
		switch.addMulticastGroup(mgid=bcast_mgid, ports=range(2, 6))
		switch.insertTableEntry(
			table_name="MyIngress.fwd_l2",
			match_fields={"hdr.ethernet.dstAddr": "ff:ff:ff:ff:ff:ff"},
			action_name="MyIngress.set_mgid",
			action_params={"mgid": bcast_mgid},
		)

'''
Function to add table entries to forward packets to the CPU
'''

def init_control_plane_interfaces(switches, interfaces, routers):
	for switch_idx, switch in enumerate(switches):
		router = routers[switch_idx]
		for interface in interfaces[router.name]:
			switch.insertTableEntry(
				table_name="MyIngress.local_forwarding_table",
				match_fields={"hdr.ipv4.dstAddr": interface["ip"]},
				action_name="MyIngress.send_to_cpu",
			)   

def init_host_local_routes(switches, routers, routers_to_hosts):
	for switch_idx, switch in enumerate(switches):
		router = routers[switch_idx]
		if router.name in routers_to_hosts:
			for host in routers_to_hosts[router.name]:
				switch.insertTableEntry(
					table_name="MyIngress.local_forwarding_table",
					match_fields={"hdr.ipv4.dstAddr": host["ip"]},
					action_name="MyIngress.ip_hit",
					action_params={"port": HOST_SWITCH_INGRESS_PORT, "next_hop": host["ip"]}
				)

def start_controllers(switches, routers, interfaces):
	controllers = []
	for switch_idx, switch in enumerate(switches):
		router = routers[switch_idx]
		controller = Controller(switch, router, 1, interfaces[router.name])
		controller.start()
		controllers.append(controller)
	
	return controllers


# ----------------- UTILS -----------------
def print_all_table_entries(switches):
	for switch in switches:
		switch.printTableEntries()
# ----------------- MAIN ----------------

def init_dual_simulation():
	topo = DualSwitchTopo()

	net = P4Mininet(program="router.p4", topo=topo, auto_arp=False)
	net.start()

	sw1 = net.get("s1")
	sw2 = net.get("s2")

	r1 = net.get("r1")
	r2 = net.get("r2")

	h1 = net.get("h1")
	h2 = net.get("h2")

	switches = [sw1, sw2]
	routers = [r1, r2]
	hosts = [h1, h2]

	interfaces = topo.get_router_interfaces()
	routers_to_hosts = topo.get_router_to_host_mapping()

	init_multicast(switches)
	init_control_plane_interfaces(switches, interfaces, routers)
	init_host_local_routes(switches, routers, routers_to_hosts)
	controllers = start_controllers(switches, routers, interfaces)
	return controllers

