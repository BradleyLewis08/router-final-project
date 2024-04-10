from mininet.topo import Topo

class SingleSwitchTopo(Topo):
    def __init__(self, n, **opts):
        Topo.__init__(self, **opts)

        switch = self.addSwitch("s1")

        for i in range(1, n + 1):
            host = self.addHost(
                "h%d" % i, ip="10.0.0.%d" % i, mac="00:00:00:00:00:%02x" % i
            )
            self.addLink(host, switch, port2=i)

class DoubleSwitchTopo(Topo):
    def __init__(self, n, **opts):
        Topo.__init__(self, **opts)

        # Switches
        switch1 = self.addSwitch("s1")
        switch2 = self.addSwitch("s2")

        # Hosts
        host1 = self.addHost('h1', ip='10.0.0.1/24', defaultRoute='via 10.0.0.254')
        host2 = self.addHost('h2', ip='10.0.1.1/24', defaultRoute='via 10.0.1.254')
        host3 = self.addHost('h3', ip='10.0.0.2/24', defaultRoute='via 10.0.0.254')
        host4 = self.addHost('h4', ip='10.0.1.2/24', defaultRoute='via 10.0.1.254')

        # Connect hosts to switches
        self.addLink(host1, switch1)
        self.addLink(host3, switch1)
        self.addLink(host2, switch2)
        self.addLink(host4, switch2)

        # Add direct link between switches
        self.addLink(switch1, switch2)

def get_router_interfaces(topology="SingleSwitchTopo"):
    if topology == "SingleSwitchTopo":
        return [
            {
                "ip": "10.0.1.1", 
                "mask": "255.255.255.0",
                "helloint": 5,
            }
        ]

