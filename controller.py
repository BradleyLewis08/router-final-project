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
    def __init__(self, ip, mask, helloint, neighbors=[]):
        self.ip = ip
        self.mask = mask
        self.helloint = helloint
        self.neighbors = neighbors

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

    def _create_hello_packet(self):
        packet = Ether() / IP() / PWOSPFPacket() / HelloPacket()
        packet[Ether].src = self.controller.mac_addr
        packet[Ether].dest = BCAST_ETHER_ADDR
        packet[IP].src = self.interface.ip
        packet[IP].dest = BCAST_HELLO_IP_ADDR
        packet[HelloPacket].routerId = self.interface.routerId
        packet[HelloPacket].areaId = self.interface.areaId
        packet[HelloPacket].authType = 0
        packet[HelloPacket].helloint = self.interface.helloint
        return packet

    def run(self):
        pass
        # self.debug("Running!")
        # Send hello packets every hello interval
        # while True:
        #     packet = self._create_hello_packet()
        #     self.debug("Sending hello packet:")
        #     packet.show()
        #     self.controller.send(packet)
        #     time.sleep(self.interface.helloint)

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
    routerId : str
        The router ID of the router (defaults to the IP address of the 0th interface)
    areaId : str
        The area ID of the router
    lsuint : int
        Interval between link state advertisements
    interfaces : list
        A list of interfaces on the router
    
    '''
    def __init__(self, sw, router, areaId, interfaces, lsuint=2, start_wait=0.3):
        # Assertions
        assert len(sw.intfs) > 1, "Switch must have at least one interface"
        assert start_wait >= 0, "Start wait must be non-negative"

        super(Controller, self).__init__()
        self.sw = sw
        self.areaId = areaId
        self.mac_addr = router.MAC()
        self.start_wait = start_wait # time to wait for the controller to be listenning

        self.iface = sw.intfs[1].name
        self.port_for_mac = {}
        self.mac_for_ip = {}

        self.stop_event = Event()
        self.routerId = router.IP()
        self.lsuint = lsuint

        # ----------- INTERFACES ------------
        self.interfaces = []

        self.DEBUG = False


        for interface in interfaces:
            self.interfaces.append(Interface(interface["ip"], interface["mask"], interface["helloint"]))
        
        self.adjacency_list = {}
    
    # Debug statement that can take a string and argument
    def debug(self, *args):
        if(self.debug):
            print(f"{self.routerId} - DEBUG: ", *args)

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
        self.sw.insertTableEntry(table_name='MyIngress.arp_table',
                match_fields={'next_hop_ip': ip},
                action_name='MyIngress.arp_hit',
                action_params={'mac': mac})
        self.mac_for_ip[ip] = mac

    def handleArpReply(self, pkt):
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
        self.debug(self.routerId, "Handling ARP request for ", pkt[ARP].pdst)
        self.addMacAddr(pkt[ARP].hwsrc, pkt[CPUMetadata].srcPort)
        self.addIpAddr(pkt[ARP].psrc, pkt[ARP].hwsrc) 

        # If the destination IP is one of the router's interfaces, send an ARP reply
        matched_interface = self.findInterface(pkt[ARP].pdst)

        if matched_interface is not None:
            self.debug("Matched interface: ", matched_interface.ip)
            pkt = self._constructArpReply(pkt, matched_interface)
            self.debug("Packet: ", pkt[ARP].op, pkt[ARP].hwdst, pkt[ARP].pdst, pkt[ARP].hwsrc, pkt[ARP].psrc)
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
        if pkt[HelloPacket].areaId != self.areaId:
            return False
        
        # Check 4
        if pkt[HelloPacket].authType != 0:
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
        if pkt[CPUMetadata].fromCpu == 1: return

        if ARP in pkt:
            if pkt[ARP].op == ARP_OP_REQ:
                self.handleArpRequest(pkt)
            elif pkt[ARP].op == ARP_OP_REPLY:
                self.handleArpReply(pkt)
        
        if PWOSPFPacket in pkt:
            if not self._helloPacketIsValid(pkt):
                return

            if HelloPacket in pkt:
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
