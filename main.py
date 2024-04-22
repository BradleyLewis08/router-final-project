from quad_main import init_quad_simulation
from dual_main import init_dual_simulation
from triple_main import init_triple_simulation
from square_simulation import init_square_simulation
import time

controllers, switches, hosts = init_triple_simulation()
# controllers, switches, hosts = init_quad_simulation()
# controllers, switches, hosts = init_dual_simulation()
# controllers = init_square_simulation()

print("Waiting for things to settle...")

ctr = 20
while ctr > 0:
	time.sleep(1)
	ctr -= 1
	print(ctr)

def test_pings():
	for idx, host in enumerate(hosts):
		for idx2, host2 in enumerate(hosts):
			if idx != idx2:
				print(f"Pinging {host.name} to {host2.name}")
				print(host.cmd(f"ping -c1 {host2.IP()}"))

test_pings()