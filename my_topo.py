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
            } for interface_idx in range(1, 5)
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
        }
    ]

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

        self.router_ips = [f"200.0.{i}.0" for i in range(1, 4)]
        self.host_ips = [f"200.0.{i}.10" for i in range(1, 4)]
        self.host_macs = [f"00:00:00:00:00:{i}0" for i in range(1, 4)]
        self.router_macs = [f"00:00:00:00:00:0{i}" for i in range(1, 4)]

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


class TripleSwitchTopo(Topo):
    def __init__(self, **opts):
        super(TripleSwitchTopo, self).__init__(**opts)

        self.router_names = ["r1", "r2", "r3"]
        self.switch_names = ["s1", "s2", "s3"]
        self.host_names = ["h1", "h2", "h3"]

        self.router_ips = [f"200.0.{i}.0" for i in range(1, 4)]
        self.host_ips = [f"200.0.{i}.10" for i in range(1, 4)]
        self.host_macs = [f"00:00:00:00:00:{i}0" for i in range(1, 4)]
        self.router_macs = [f"00:00:00:00:00:0{i}" for i in range(1, 4)]

        for idx, router_name in enumerate(self.router_names):
            router = self.addHost(router_name, ip=self.router_ips[idx], mac=self.router_macs[idx])
            switch = self.addSwitch(self.switch_names[idx])
            host = self.addHost(self.host_names[idx], ip=self.host_ips[idx], mac=self.host_macs[idx])


            # Link the router to the switch and then the router to the host
            self.addLink(router, switch, port2=CPU_EGRESS_PORT)
            self.addLink(host, switch, port2=HOST_SWITCH_INGRESS_PORT)
        
        # Link the switches to each other
        self.addLink(self.switch_names[0], self.switch_names[1], port1=2, port2=3)
        self.addLink(self.switch_names[1], self.switch_names[2], port1=2, port2=3)
        self.addLink(self.switch_names[2], self.switch_names[0], port1=2, port2=3)

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
        self.addLink(self.switch_names[3], self.switch_names[0], port1=3, port2=3)

    def get_router_interfaces(self):
        return get_router_interfaces(self.router_names)
    
    def get_router_to_host_mapping(self):
        return get_router_to_host_mapping(self.router_names, self.host_names, self.host_ips, self.host_macs)

class SquareSwitchesTopo(Topo):
    def __init__(self, **opts):
        Topo.__init__(self, **opts)
        # Set up 4 routers
        s1 = self.addSwitch('s1')
        cpu1 = self.addHost('r1', ip='100.0.1.1')
        self.addLink(cpu1, s1, port2=1)

        s2 = self.addSwitch('s2')
        cpu2 = self.addHost('r2', ip='100.0.2.1')
        self.addLink(cpu2, s2, port2=1)

        s3 = self.addSwitch('s3')
        cpu3 = self.addHost('r3', ip='100.0.3.1')
        self.addLink(cpu3, s3, port2=1)

        s4 = self.addSwitch('s4')
        cpu4 = self.addHost('r4', ip='100.0.4.1')
        self.addLink(cpu4, s4, port2=1)

        # Connect routers in square with 1-3 diagonal connection
        self.addLink(s1, s2, port1=2, port2=2)
        self.addLink(s2, s3, port1=3, port2=2)
        self.addLink(s3, s4, port1=3, port2=2)
        self.addLink(s4, s1, port1=3, port2=3)
        self.addLink(s1, s3, port1=5, port2=5)

        # Add host at each router
        h1 = self.addHost('h1', ip='100.0.1.10')
        self.addLink(h1, s1, port2=4)

        h2 = self.addHost('h2', ip='100.0.2.10')
        self.addLink(h2, s2, port2=4)

        h3 = self.addHost('h3', ip='100.0.3.10')
        self.addLink(h3, s3, port2=4)

        h4 = self.addHost('h4', ip='100.0.4.10')
        self.addLink(h4, s4, port2=4)
    
    def get_router_interfaces(self):
        return {
            'r1': [{
                'ip': i[0],
                'mask': i[1],
                'helloint': HELLO_INTERVAL,
                'port': i[3]
            } for i in s1_intfs],
            'r2': [{
                'ip': i[0],
                'mask': i[1],
                'helloint': HELLO_INTERVAL,
                'port': i[3]
            } for i in s2_intfs],
            'r3': [{
                'ip': i[0],
                'mask': i[1],
                'helloint': HELLO_INTERVAL,
                'port': i[3]
            } for i in s3_intfs],
            'r4': [{
                'ip': i[0],
                'mask': i[1],
                'helloint': HELLO_INTERVAL,
                'port': i[3]
            } for i in s4_intfs]
        }

    def get_router_to_host_mapping(self):
        router_to_hosts = {}
        for i in range(1, 5):
            router_to_hosts[f'r{i}'] = [{
                'name': f'h{i}',
                'ip': f'100.0.{i}.10',
                'mac': f'00:00:00:00:00:{i}0',
                'port': ROUTER_HOST_EGRESS_PORT
            }]
        return router_to_hosts

    