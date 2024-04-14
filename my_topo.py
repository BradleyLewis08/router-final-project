from mininet.topo import Topo
from mininet.link import Intf


MASK = "255.255.255.0"

CPU_EGRESS_PORT = 1
ROUTER_HOST_EGRESS_PORT = 2
HOST_SWITCH_INGRESS_PORT = 4
HELLO_INTERVAL = 5

def get_router_interfaces(router_names):
    router_interfaces = {}

    for i, router_name in enumerate(router_names):
        router_idx = i + 1
        interfaces = [
            {
                "ip": f"200.0.{router_idx}.{interface_idx}",
                "mask": MASK,
                "helloint": HELLO_INTERVAL,
                "port": interface_idx,
            } for interface_idx in range(1, 4)
        ]
        router_interfaces[router_name] = interfaces

    return router_interfaces

def get_router_to_host_mapping(router_names, host_names, host_ips, host_macs):
    router_to_hosts = {}

    for i in range(len(router_names)):
        router_name = router_names[i]
        host_name = host_names[i]
        host_ip = host_ips[i]
        host_mac = host_macs[i] 

        router_to_hosts[router_name] = [{
            "name": host_name,
            "ip": host_ip,
            "mac": host_mac,
            "port": ROUTER_HOST_EGRESS_PORT
        }]

    return router_to_hosts

class SingleSwitchTopo(Topo):
    def __init__(self, **opts):
        super(SingleSwitchTopo, self).__init__(**opts)

        self.router_names = ["r1"]
        self.switch_names = ["s1"]
        self.host_names = ["h1", "h2"]

        self.router_ips = [f"200.0.{1}.0"]
        self.host_ips = [f"200.0.{1}.10", f"200.0.{1}.20"]
        self.host_macs = [f"00:00:00:00:00:{1}0", f"00:00:00:00:00:{1}1"]

        self.router_macs = [f"00:00:00:00:00:0{1}"]

        router = self.addHost(self.router_names[0], ip=self.router_ips[0], mac=self.router_macs[0])
        switch = self.addSwitch(self.switch_names[0])
        host1 = self.addHost(self.host_names[0], ip=self.host_ips[0], mac=self.host_macs[0])
        host2 = self.addHost(self.host_names[1], ip=self.host_ips[1], mac=self.host_macs[1])

        self.addLink(router, switch, port2=CPU_EGRESS_PORT)
        self.addLink(host1, switch, port2=HOST_SWITCH_INGRESS_PORT)
        self.addLink(host2, switch, port2=HOST_SWITCH_INGRESS_PORT + 1)

    def get_router_interfaces(self):
        return get_router_interfaces(self.router_names)
    
    def get_router_to_host_mapping(self):
        return get_router_to_host_mapping(self.router_names, self.host_names, self.host_ips, self.host_macs)


class DualSwitchTopo(Topo):
    def __init__(self, **opts):
        super(DualSwitchTopo, self).__init__(**opts)

        self.router_names = ["r1", "r2"]
        self.switch_names = ["s1", "s2"]
        self.host_names = ["h1", "h2"]

        self.router_ips = [f"200.0.{i}.0" for i in range(1, 3)]
        self.host_ips = [f"200.0.{i}.10" for i in range(1, 3)]
        self.host_macs = [f"00:00:00:00:00:{i}0" for i in range(1, 3)]
        self.router_macs = [f"00:00:00:00:00:0{i}" for i in range(1, 3)]

        for idx, router_name in enumerate(self.router_names):
            router = self.addHost(router_name, ip=self.router_ips[idx], mac=self.router_macs[idx])
            switch = self.addSwitch(self.switch_names[idx])
            host = self.addHost(self.host_names[idx], ip=self.host_ips[idx], mac=self.host_macs[idx])

            # Link the router to the switch and then the router to the host
            self.addLink(router, switch, port2=CPU_EGRESS_PORT)
            self.addLink(host, switch, port2=HOST_SWITCH_INGRESS_PORT)
        
        # Link the switches to each other
        self.addLink(self.switch_names[0], self.switch_names[1], port1=2, port2=2)

    def get_router_interfaces(self):
        return get_router_interfaces(self.router_names)
    
    def get_router_to_host_mapping(self):
        return get_router_to_host_mapping(self.router_names, self.host_names, self.host_ips, self.host_macs)

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

    def get_router_interfaces(self):
        return get_router_interfaces(self.router_names)
    
    def get_router_to_host_mapping(self):
        return get_router_to_host_mapping(self.router_names, self.host_names, self.host_ips, self.host_macs)





