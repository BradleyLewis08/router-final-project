from threading import Thread, Event
from scapy.all import sendp
from scapy.all import Packet, Ether, IP, ARP
from async_sniff import sniff
from cpu_metadata import CPUMetadata
from packets import PWOSPFPacket, HelloPacket, LSUPacket, LSUAdvertisement
import time
from constants import *

def neighborFactory(routerId, interfaceIp):
	return {
		"routerId": routerId,
		"interfaceIp": interfaceIp,
		"lastHelloTime": time.time()
	}

class Interface(Thread):
    def __init__(self, ip, mask, helloint, port, controller):
        super(Interface, self).__init__()
        self.ip = ip
        self.mask = mask
        self.helloint = helloint
        self.neighbors = []
        self.port = port
        self.controller = controller
        self.DEBUG = False

    def hasNeighbor(self, routerId, interfaceIp):
        for idx, neighbor in enumerate(self.neighbors):
            if neighbor["routerId"] == routerId and neighbor["interfaceIp"] == interfaceIp:
                return idx
        return -1

    def getInterfaceIpFromRouterId(self, routerId):
        for neighbor in self.neighbors:
            if neighbor["routerId"] == routerId:
                return neighbor["interfaceIp"]
        return None

    def handleNeighbor(self, neighbor):
        neighbor_idx = self.hasNeighbor(neighbor["routerId"], neighbor["interfaceIp"])
        if neighbor_idx == -1:
            self.neighbors.append(neighbor)
        else:
            self.neighbors[neighbor_idx]["lastHelloTime"] = time.time()

    def debug(self, *args):
        if(self.DEBUG):
            print(f"INTERFACE: {self.ip} - DEBUG: ", *args)
    
    def __str__(self):
        ret = f"Router {self.controller.router_id} Interface {self.ip}:\n"
        ret += "NEIGHBORS:\n"
        for neighbor in self.neighbors:
            ret += f"Router ID: {neighbor['routerId']}, Interface IP: {neighbor['interfaceIp']}, Last Hello Time: {neighbor['lastHelloTime']}\n"
        
        return ret
        
    def _hello_ether_encap(self, pkt):
        pkt[Ether].src = self.controller.mac_addr
        pkt[Ether].dst = BCAST_ETHER_ADDR
    
    def _hello_cpu_encap(self, pkt):
        pkt[CPUMetadata].fromCpu = 1
        pkt[CPUMetadata].origEtherType = CPU_ORIG_ETHER_TYPE
        pkt[CPUMetadata].srcPort = 1
        pkt[CPUMetadata].dstPort = self.port
        pkt[CPUMetadata].isHelloPacket = 1

    def _hello_ip_encap(self, pkt):
        pkt[IP].src = self.ip
        pkt[IP].dst = BCAST_HELLO_IP_ADDR
        pkt[IP].proto = OSPF_PROTOCOL_NUMBER

    def _hello_PWOSPF_encap(self, pkt):
        pkt[PWOSPFPacket].version = 2
        pkt[PWOSPFPacket].type = OSPF_HELLO_TYPE
        pkt[PWOSPFPacket].packet_length = 0
        pkt[PWOSPFPacket].router_id = self.controller.router_id
        pkt[PWOSPFPacket].area_id = self.controller.area_id
        pkt[PWOSPFPacket].checksum = 0

    def _hello_encap(self, pkt):
        pkt[HelloPacket].network_mask = self.mask
        pkt[HelloPacket].hello_int = self.helloint

    def _create_hello_packet(self):
        packet = Ether() / CPUMetadata() / IP() / PWOSPFPacket() / HelloPacket()
        self._hello_ether_encap(packet)
        self._hello_cpu_encap(packet)
        # self.debug("Creating hello packet with dstPort", packet[CPUMetadata].dstPort)
        self._hello_ip_encap(packet)
        self._hello_PWOSPF_encap(packet)
        self._hello_encap(packet)
        return packet

    def run(self):
        if self.port == 1:
            return

        while True:
            packet = self._create_hello_packet()
            self.controller.send(packet)
            time.sleep(self.helloint)
    