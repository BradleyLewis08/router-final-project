from quad_main import init_quad_simulation
from dual_main import init_dual_simulation
from triple_main import init_triple_simulation
from square_simulation import init_square_simulation
import time

# Triangle simulation
controllers, switches, hosts = init_triple_simulation()

print("Waiting for things to settle...")

ctr = 10
while ctr > 0:
	time.sleep(1)
	ctr -= 1
	print(ctr)

# Ping every router interface from host 0
anchor = hosts[0]
for controller in controllers[1:]:
	for interface in controller.interfaces:
		print(anchor.cmd(f"ping -c1 {interface.ip}"))

# Ping every host from host 1
anchor = hosts[1]
for host in hosts:
	if host == anchor:
		continue
	print(anchor.cmd(f"ping -c1 {host.IP()}"))

# Print counters
for controller in controllers:
	controller.print_counters()