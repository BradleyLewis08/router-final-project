from quad_main import init_quad_simulation
from dual_main import init_dual_simulation
from triple_main import init_triple_simulation
from square_simulation import init_square_simulation
import time

# controllers, switches, hosts = init_triple_simulation()
# controllers, switches, hosts = init_quad_simulation()
controllers, switches, hosts = init_dual_simulation()
# controllers = init_square_simulation()

# print("Waiting for things to settle...")

ctr = 15
while ctr > 0:
	time.sleep(1)
	ctr -= 1
	print(ctr)

switches[0].printTableEntries()
switches[1].printTableEntries()

# print(hosts[0].cmd("ip addr"))

print(hosts[0].cmd("ping -c1 200.0.2.1"))
print(hosts[0].cmd("ping -c1 200.0.2.2"))
print(hosts[0].cmd("ping -c1 200.0.2.10"))

print("HOST 2 PINGING")

print(hosts[1].cmd("ping -c1 200.0.1.1"))
print(hosts[1].cmd("ping -c1 200.0.1.2"))
print(hosts[1].cmd("ping -c1 200.0.1.3"))
print(hosts[1].cmd("ping -c1 200.0.1.4"))
print(hosts[1].cmd("ping -c1 200.0.1.7"))
print(hosts[1].cmd("ping -c1 200.0.1.10"))

# print(hosts[0].cmd("ping -c1 200.0.2.20"))
# print(hosts[0].cmd("ping -c1 200.0.2.20"))

# switches[0].printTableEntries()
# switches[1].printTableEntries()
# switches[2].printTableEntries()
# switches[2].printTableEntries()
# switches[3].printTableEntries()

# print("Pinging other hosts")
# print(hosts[0].cmd("ping -c1 -v 200.0.2.10"))
# print(hosts[0].cmd("ping -c1 -v 200.0.3.10"))
# print("\n")

# print("Pinging other interfaces")
# print(hosts[0].cmd("ping -c1 -v 200.0.2.1"))
# print(hosts[0].cmd("ping -c1 -v 200.0.2.2"))
# print(hosts[0].cmd("ping -c1 -v 200.0.2.3"))
# print(hosts[0].cmd("ping -c1 -v 200.0.2.7"))

# print(hosts[0].cmd("ping -c1 -v 200.0.3.1"))
# print(hosts[0].cmd("ping -c1 -v 200.0.3.2"))
# print(hosts[0].cmd("ping -c1 -v 200.0.3.3"))
# print(hosts[0].cmd("ping -c1 -v 200.0.3.7"))













