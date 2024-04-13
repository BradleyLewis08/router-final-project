import sys
sys.path.append("/home/bradleylewis/p4app/docker/scripts")
sys.path.append("/home/bradleylewis/p4-build/p4dev-python-venv/lib/python3.10/site-packages")

from p4app import P4Mininet

from controller import Controller
from my_topo import SingleSwitchTopo, DoubleSwitchTopo, get_router_interfaces

# Add three hosts. Port 1 (h1) is reserved for the CPU.
N = 3

topo = DoubleSwitchTopo(N)
interfaces = topo.get_router_interfaces()

net = P4Mininet(program="router.p4", topo=topo, auto_arp=False)
net.start()

# Add a mcast group for all ports (except for the CPU port)
bcast_mgid = 1
sw1 = net.get("s1")
sw2 = net.get("s2")
r1 = net.get("r1")
r2 = net.get("r2")

sw1.addMulticastGroup(mgid=bcast_mgid, ports=range(2, N + 1))

# Send MAC bcast packets to the bcast multicast group
sw1.insertTableEntry(
    table_name="MyIngress.fwd_l2",
    match_fields={"hdr.ethernet.dstAddr": ["ff:ff:ff:ff:ff:ff"]},
    action_name="MyIngress.set_mgid",
    action_params={"mgid": bcast_mgid},
)

sw2.insertTableEntry(
    table_name="MyIngress.fwd_l2",
    match_fields={"hdr.ethernet.dstAddr": ["ff:ff:ff:ff:ff:ff"]},
    action_name="MyIngress.set_mgid",
    action_params={"mgid": bcast_mgid},
)

# ------- Add routing rules to forward local ip matches -------

# s1, h1
sw1.insertTableEntry(
    table_name="MyIngress.local_forwarding_table",
    match_fields={"hdr.ipv4.dstAddr": '100.0.1.10'},
    action_name="MyIngress.ip_forward",
    action_params={ "port": 2, "dstAddr": "100.0.1.10"},
)

# s2, h2
sw2.insertTableEntry(
	table_name="MyIngress.local_forwarding_table",
	match_fields={"hdr.ipv4.dstAddr": '100.0.2.10'},
	action_name="MyIngress.ip_forward",
	action_params={ "port": 2, "dstAddr": "100.0.2.10"},
)

# ------- Add routing rules to allow forwarding to control plane -------

sw1.insertTableEntry(
	table_name="MyIngress.local_forwarding_table",
	match_fields={"hdr.ipv4.dstAddr": "100.0.1.1"},
	action_name="MyIngress.send_to_cpu",
)

sw2.insertTableEntry(
	table_name="MyIngress.local_forwarding_table",
	match_fields={"hdr.ipv4.dstAddr": "100.0.2.1"},
	action_name="MyIngress.send_to_cpu",
)

# Start the MAC learning controller
cpu1 = Controller(sw1, r1, 1, interfaces["r1"]) 
cpu2 = Controller(sw2, r2, 1, interfaces["r2"])
cpu1.start()
cpu2.start()

sw1.printTableEntries()
sw2.printTableEntries()

h1, h2 = net.get("h1"), net.get("h2")
print("Pingall: ", h2.cmd("pingall"))
# print(h3.cmd("ping -c1 10.0.0.2"))

# These table entries were added by the CPU:
sw1.printTableEntries()
sw2.printTableEntries()
