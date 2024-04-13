from mininet.topo import Topo
from mininet.link import Intf


MASK = "255.255.255.0"

CPU_EGRESS_PORT = 1
ROUTER_HOST_EGRESS_PORT = 2
HOST_SWITCH_INGRESS_PORT = 4
HELLO_INTERVAL = 5

routers = []
hosts = []

for i in range(1, 5):
    router = {
        "name": f"r{i}",
        "ip": f"100.0.{i}.1",
        "mask": MASK,
        "helloint": 5,
        "mac": f"00:00:00:00:00:0{i}"
    }

    host = {
        "name": f"h{i}",
        "ip": f"100.0.{i}.10",
        "mac": f"00:00:00:00:00:{i * 16}"
    }

    routers.append(router)
    hosts.append(host)


class SingleSwitchTopo(Topo):
    def __init__(self, n, **opts):
        Topo.__init__(self, **opts)

        switch = self.addSwitch("s1")

        for i in range(2, n + 1):
            host = self.addHost(
                "h%d" % i, ip="10.0.0.%d" % i, mac="00:00:00:00:00:%02x" % i
            )
            self.addLink(host, switch, port2=i)
        
        router = self.addHost("r1", ip="100.0.1.1")
        self.addLink(router, switch, port2=1)


class QuadSwitchTopo(Topo):
    def __init__(self, **opts):
        super(QuadSwitchTopo, self).__init__(**opts)

        self.router_names = [f"r{i}" for i in range(1, 5)]
        self.switch_names = [f"s{i}" for i in range(1, 5)]
        self.host_names = [f"h{i}" for i in range(1, 5)]
        
        self.router_ips = [f"200.0.{i}.0" for i in range(1, 5)]
        self.host_ips = [f"200.0.{i}.10" for i in range(1, 5)]
        self.host_macs = [f"00:00:00:00:00:{i}0" for i in range(1, 5)]
        self.router_macs = [f"00:00:00:00:00:0{i}" for i in range(1, 5)]

        # Iterating through each index in the lists
        for idx, router_name in enumerate(self.router_names):
            router = self.addHost(router_name, ip=self.router_ips[idx], mac=self.router_macs[idx])
            switch = self.addSwitch(self.switch_names[idx])
            host = self.addHost(self.host_names[idx], ip=self.host_ips[idx], mac=self.host_macs[idx])

            # Link the router to the switch and then the router to the host
            self.addLink(router, switch, port2=CPU_EGRESS_PORT)
            self.addLink(host, switch, port2=HOST_SWITCH_INGRESS_PORT)


        # Link switches to each other
        self.addLink(self.switch_names[0], self.switch_names[1], port1=2, port2=2)
        self.addLink(self.switch_names[1], self.switch_names[2], port1=3, port2=2)
        self.addLink(self.switch_names[2], self.switch_names[3], port1=3, port2=2)
        # self.addLink(self.switch_names[3], self.switch_names[0], port1=3, port2=4)

    def get_router_interfaces(self):
        router_interfaces = {}

        for i, router_name in enumerate(self.router_names):
            router_idx = i + 1
            interfaces = [
                {
                    "ip": f"200.0.{router_idx}.{interface_idx}",
                    "mask": MASK,
                    "helloint": HELLO_INTERVAL
                } for interface_idx in range(1, 6)
            ]
            router_interfaces[router_name] = interfaces

        return router_interfaces
    
    def get_router_to_host_mapping(self):
        router_to_hosts = {}

        for i in range(len(self.router_names)):
            router_name = self.router_names[i]
            host_name = self.host_names[i]
            host_ip = self.host_ips[i]
            host_mac = self.host_macs[i] 

            router_to_hosts[router_name] = [{
                "name": host_name,
                "ip": host_ip,
                "mac": host_mac,
                "port": ROUTER_HOST_EGRESS_PORT
            }]

        return router_to_hosts





