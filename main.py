from quad_main import init_quad_simulation
from dual_main import init_dual_simulation
from triple_main import init_triple_simulation
from square_simulation import init_square_simulation
import time

controllers = init_triple_simulation()
# controllers = init_quad_simulation()
# controllers = init_dual_simulation()
# controllers = init_square_simulation()

print("Waiting for things to settle...")

ctr = 10
while ctr > 0:
	time.sleep(1)
	ctr -= 1
	print(ctr)

for controller in controllers:
	controller.print_topology_database()









