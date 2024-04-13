from threading import Thread, Event
from scapy.all import sendp
from scapy.all import Packet, Ether, IP, ARP
from async_sniff import sniff
from cpu_metadata import CPUMetadata
from packets import PWOSPFPacket, HelloPacket, LSUPacket, LSUAdvertisement
import time

ARP_OP_REQ   = 0x0001
ARP_OP_REPLY = 0x0002

BCAST_ETHER_ADDR = "ff:ff:ff:ff:ff:ff"
BCAST_HELLO_IP_ADDR = "224.0.0.5"
OSPF_HELLO_TYPE = 1
OSPF_LSU_TYPE = 4

OSPF_PROTOCOL_NUMBER = 89

CPU_ORIG_ETHER_TYPE = 0x0800




'''
Represents a single interface on a router
...

Attributes
----------
ip : str
    The IP address of the interface
mask : str
    The subnet mask of the interface
helloint : int
    The hello interval of the interface
neighbors : list
    A list of neighbors connected to the interface
'''
class Interface():
    def __init__(self, ip, mask, helloint, port, neighbors=[]):
        self.ip = ip
        self.mask = mask
        self.helloint = helloint
        self.neighbors = neighbors
        self.port = port

'''
Thread responsible for sending hello packets to neighbors for a given interface

Attributes
----------
    interface : Interface
        The interface to send hello packets on
    controller: Controller
        The controller of the router (for getting controller's details and sending packets)
'''
class HelloPacketSender(Thread):
    def __init__(self, interface, controller):
        super(HelloPacketSender, self).__init__()
        self.interface = interface
        self.controller = controller
        self.DEBUG = True

    def debug(self, *args):
        if(self.DEBUG):
            print(f"{self.interface.ip} - DEBUG: ", *args)
    
    def ether_encap(self, pkt):
        pkt[Ether].src = self.controller.mac_addr
        pkt[Ether].dst = BCAST_ETHER_ADDR
    
    def cpu_encap(self, pkt):
        pkt[CPUMetadata].fromCpu = 1
        pkt[CPUMetadata].origEtherType = CPU_ORIG_ETHER_TYPE
        pkt[CPUMetadata].srcPort = 1
        pkt[CPUMetadata].dstPort = self.interface.port
        pkt[CPUMetadata].isHelloPacket = 1

    def ip_encap(self, pkt):
        pkt[IP].src = self.interface.ip
        pkt[IP].dst = BCAST_HELLO_IP_ADDR
        pkt[IP].proto = OSPF_PROTOCOL_NUMBER

    def PWOSPF_encap(self, pkt):
        pkt[PWOSPFPacket].version = 2
        pkt[PWOSPFPacket].type = OSPF_HELLO_TYPE
        pkt[PWOSPFPacket].packet_length = 0
        pkt[PWOSPFPacket].router_id = self.controller.router_id
        pkt[PWOSPFPacket].area_id = self.controller.area_id
        pkt[PWOSPFPacket].checksum = 0

    def hello_encap(self, pkt):
        pkt[HelloPacket].network_mask = self.interface.mask
        pkt[HelloPacket].hello_int = self.interface.helloint

    def _create_hello_packet(self):
        packet = Ether() / CPUMetadata() / IP() / PWOSPFPacket() / HelloPacket()
        self.ether_encap(packet)
        self.cpu_encap(packet)
        self.ip_encap(packet)
        self.PWOSPF_encap(packet)
        self.hello_encap(packet)
        return packet

    def run(self):
        pass
        # if self.interface.port == 1:
        #     return
        # packet = self._create_hello_packet()
        # # packet.show()
        # self.controller.send(packet)
        # time.sleep(self.interface.helloint)

class Controller(Thread):
    '''
    A controller that listens for packets from the switch

    Attributes
    ----------
    sw : P4Switch
        The switch to listen for packets from
    start_wait : float
        The time to wait for the controller to be listening
    iface : str
        The interface to listen for packets on
    port_for_mac : dict
        A dictionary of MAC addresses to port numbers
    mac_for_ip : dict
        A dictionary of IP addresses to MAC addresses
    stop_event : Event
        An event to signal the controller to stop listening
    router_id : str
        The router ID of the router (defaults to the IP address of the 0th interface)
    area_id : str
        The area ID of the router
    lsuint : int
        Interval between link state advertisements
    interfaces : list
        A list of interfaces on the router
    
    '''
    def __init__(self, sw, router, area_id, interfaces, lsuint=2, start_wait=0.3):
        # Assertions
        assert len(sw.intfs) > 1, "Switch must have at least one interface"
        assert start_wait >= 0, "Start wait must be non-negative"

        super(Controller, self).__init__()
        self.sw = sw
        self.area_id = area_id
        self.mac_addr = router.MAC()
        self.start_wait = start_wait # time to wait for the controller to be listenning

        self.iface = sw.intfs[1].name
        self.port_for_mac = {}
        self.mac_for_ip = {}

        self.stop_event = Event()
        self.router_id = router.IP()
        self.lsuint = lsuint

        # ----------- INTERFACES ------------
        self.interfaces = []

        self.DEBUG = True

        for interface in interfaces:
            self.interfaces.append(Interface(interface["ip"], interface["mask"], interface["helloint"], interface["port"]))
        
        self.adjacency_list = {}

        # ----------- HELLO packets ------------
        self.hello_packet_senders = [HelloPacketSender(self.interfaces[i], self) for i in range(len(self.interfaces))]

        # # Start the hello packet senders
        # for sender in self.hello_packet_senders:
        #     sender.start()

    # Debug statement that can take a string and argument
    def debug(self, *args):
        if(self.DEBUG):
            print(f"{self.router_id} - DEBUG: ", *args)

    def findInterface(self, ip):
        for interface in self.interfaces:
            if interface.ip == ip:
                return interface
        return None 

    def addMacAddr(self, mac, port):
        # Don't re-add the mac-port mapping if we already have it:
        if mac in self.port_for_mac: return

        self.sw.insertTableEntry(table_name='MyIngress.fwd_l2',
                match_fields={'hdr.ethernet.dstAddr': [mac]},
                action_name='MyIngress.set_egr',
                action_params={'port': port})
        self.port_for_mac[mac] = port
        self.debug(f"Added MAC-Port mapping: {mac} -> {port}")
    
    def addIpAddr(self, ip, mac):
        # Don't re-add the ip-mac mapping if we already have it:
        if ip in self.mac_for_ip: return
        self.debug("Adding IP-MAC mapping: ", ip, mac)
        self.sw.insertTableEntry(table_name='MyIngress.arp_table',
                match_fields={'next_hop_ip': ip},
                action_name='MyIngress.arp_hit',
                action_params={'mac': mac})
        self.mac_for_ip[ip] = mac

    def handleArpReply(self, pkt):
        self.debug(self.router_id, "Handling ARP reply for ", pkt[ARP].pdst)
        self.addMacAddr(pkt[ARP].hwsrc, pkt[CPUMetadata].srcPort)
        self.addIpAddr(pkt[ARP].psrc, pkt[ARP].hwsrc)
        self.send(pkt)
    
    def _setArpHeaders(self, pkt, matched_interface):
        pkt[ARP].op = ARP_OP_REPLY
        pkt[ARP].hwdst = pkt[ARP].hwsrc
        pkt[ARP].pdst = pkt[ARP].psrc
        pkt[ARP].hwsrc = self.mac_addr
        pkt[ARP].psrc = matched_interface.ip
        return pkt

    def _reverseEthernet(self, pkt):
        pkt[Ether].src, pkt[Ether].dst = self.mac_addr, pkt[Ether].src
        return pkt

    def _constructArpReply(self, pkt, matched_interface):
        pkt = self._setArpHeaders(pkt, matched_interface)
        pkt = self._reverseEthernet(pkt)
        return pkt

    def handleArpRequest(self, pkt):
        self.debug("Handling ARP request")
        pkt.show()
        # self.debug(self.router_id, "Handling ARP request for ", pkt[ARP].pdst)
        self.addMacAddr(pkt[ARP].hwsrc, pkt[CPUMetadata].srcPort)
        self.addIpAddr(pkt[ARP].psrc, pkt[ARP].hwsrc) 

        # If the destination IP is one of the router's interfaces, send an ARP reply
        matched_interface = self.findInterface(pkt[ARP].pdst)

        if matched_interface is not None:
            pkt = self._constructArpReply(pkt, matched_interface)
        self.send(pkt)
    
    '''
    Hello Packet Validation
    -----------
    1) The version number field must specify protocol version 2.

    2) The 16-bit checksum on the PWOSPF packet's contents must be
    verified. (the 64-bit authentication field must be excluded
    from the checksum calculation)

    3) The area ID found in the PWOSPF header must match the Area ID
    of the receiving router.

    4) The Authentication type specified must match the authentication type
    of the receiving router.
    '''
    def _helloPacketIsValid(self, pkt):
        # Check 1
        if pkt[HelloPacket].version != 2:
            return False

        # TODO: Check 2

        # Check 3
        if pkt[HelloPacket].area_id != self.area_id:
            return False
        
        # Check 4
        if pkt[HelloPacket].autype != 0:
            return False    

        return True

    def handleHelloPacket(self, pkt):
        if not self._helloPacketIsValid(pkt):
            return

    def handlePkt(self, pkt):
        # Ignore packets without CPU metadata
        if CPUMetadata not in pkt:
            return
        
        # Ignore packets that the CPU sends:
        if pkt[CPUMetadata].fromCpu == 1: 
            # print("Ignoring packet from CPU")
            # pkt.show()
            return

        if ARP in pkt:
            if pkt[ARP].op == ARP_OP_REQ:
                self.handleArpRequest(pkt)
            elif pkt[ARP].op == ARP_OP_REPLY:
                self.handleArpReply(pkt)

        if PWOSPFPacket in pkt:
            self.debug("Received PWOSPF packet")
            if not self._helloPacketIsValid(pkt):
                return

            if HelloPacket in pkt:
                self.debug("Received Hello packet")
                self.handleHelloPacket(pkt)

    def send(self, *args, **override_kwargs):
        pkt = args[0]
        assert CPUMetadata in pkt, "Controller must send packets with special header"
        pkt[CPUMetadata].fromCpu = 1
        kwargs = dict(iface=self.iface, verbose=False)
        kwargs.update(override_kwargs)
        sendp(*args, **kwargs)

    def run(self):
        sniff(iface=self.iface, prn=self.handlePkt, stop_event=self.stop_event)

    def start(self, *args, **kwargs):
        super(Controller, self).start(*args, **kwargs)
        time.sleep(self.start_wait)
        for interface in self.interfaces:
            HelloPacketSender(interface, self).start()

    def join(self, *args, **kwargs):
        self.stop_event.set()
        super(Controller, self).join(*args, **kwargs)
