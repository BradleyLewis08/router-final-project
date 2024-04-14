import sys
import time
import json
sys.path.append("/home/bradleylewis/p4app/docker/scripts")
sys.path.append("/home/bradleylewis/p4-build/p4dev-python-venv/lib/python3.10/site-packages")
from tests import test_ping_all_router_interfaces

from p4app import P4Mininet

from controller import Controller
from my_topo import SingleSwitchTopo

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

def init_control_plane_interfaces(switches, interfaces, routers):
    for switch_idx, switch in enumerate(switches):
        router = routers[switch_idx]
        for interface in interfaces[router.name]:
            print(interface, router.name)
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
                    action_params={"port": 4, "next_hop": host["ip"]}
                )



def start_controllers(switches, routers, interfaces):
    for switch_idx, switch in enumerate(switches):
        router = routers[switch_idx]
        controller = Controller(switch, router, 1, interfaces[router.name])
        controller.start()

# ----------------- UTILS -----------------
def print_all_table_entries(switches):
    for switch in switches:
        switch.printTableEntries()
# ----------------- MAIN ----------------

topo = SingleSwitchTopo()

net = P4Mininet(program="router.p4", topo=topo, auto_arp=False)
net.start()

# Add a mcast group for all ports (except for the CPU port)
sw1 = net.get("s1")

r1 = net.get("r1")

h1 = net.get("h1")
h2 = net.get("h2")

switches = [sw1]
routers = [r1]
hosts = [h1, h2] 

interfaces = {
    "r1": [
        {
            "ip": "200.0.1.1",
            "mask": "255.255.255.0",
            "helloint": 5,
            "port": 1
        },
        {
            "ip": "200.0.1.2",
            "mask": "255.255.255.0",
            "helloint": 5,
            "port": 2
        },
        {
            "ip": "200.0.1.3",
            "mask": "255.255.255.0",
            "helloint": 5,
            "port": 3
        }
    ]
}

routers_to_hosts = {
    "r1": [
        {
            "name": "h1",
            "ip": "200.0.1.10",
            "mac": "00:00:00:00:00:10",
            "port": 4
        },
        {
            "name": "h2",
			"ip": "200.0.1.20",
			"mac": "00:00:00:00:00:20",
            "port": 5
		}
    ]
}


init_multicast(switches)
init_control_plane_interfaces(switches, interfaces, routers)
init_host_local_routes(switches, routers, routers_to_hosts)
start_controllers(switches, routers, interfaces)


h1 = net.get("h1")

# print_all_table_entries(switches)

# print("Pingall: ", h2.cmd("pingall"))
sw1.printTableEntries()

print(h1.cmd("ping -c1 200.0.1.20"))
# print(h1.cmd("ping -c1 200.0.2.2"))
sw1.printTableEntries()
# sw2.printTableEntries()
# test_ping_all_router_interfaces(hosts, routers, interfaces)
# print(h1.cmd("pingall"))

# print_all_table_entries(switches)

# sw3.printTableEntries()
# print(h1.cmd("arping -c1 100.0.0.2"))


# These table entries were added by the CPU:
sw1.printTableEntries()

# while True:
#     print("Switch 1 hello packets: ", sw1.readCounter('hello_packets', 1)[0])
#     print("Switch 2 hello packets: ", sw2.readCounter('hello_packets', 1)[0])

#     print("Switch 1 cpu_packets: ", sw1.readCounter('cpu_packets', 1)[0])
#     print("Switch 2 cpu_packets: ", sw2.readCounter('cpu_packets', 1)[0])

#     print("Switch 1 routed_packets: ", sw1.readCounter('routed_packets', 1)[0])
#     print("Switch 2 routed_packets: ", sw2.readCounter('routed_packets', 1)[0])

#     print("Switch 1 ethernet_packets: ", sw1.readCounter('ethernet_packets', 1)[0])
#     print("Switch 2 ethernet_packets: ", sw2.readCounter('ethernet_packets', 1)[0])

#     time.sleep(3)
