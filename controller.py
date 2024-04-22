from heapq import heappop, heappush
from collections import defaultdict
from threading import Thread, Event
from scapy.all import sendp
from scapy.all import Packet, Ether, IP, ARP, ICMP
from async_sniff import sniff
from cpu_metadata import CPUMetadata
from packets import PWOSPFPacket, HelloPacket, LSUPacket, LSUAdvertisement
import ipaddress
from LSU import LSU

import time
import json

from constants import *
from interface import Interface, neighborFactory

class InterfaceHelloMonitor(Thread):
    def __init__(self, controller):
        super(InterfaceHelloMonitor, self).__init__()
        self.controller = controller
        self.stop_event = Event()
    
    def run(self):
        while not self.stop_event.is_set():
            changed_interfaces = []
            for interface in self.controller.interfaces:
                for neighbor in interface.neighbors:
                    if time.time() - neighbor["lastHelloTime"] > interface.helloint * 3:
                        interface.neighbors.remove(neighbor)
                        changed_interfaces.append(interface)
            
            if len(changed_interfaces) > 0:
                for interface in changed_interfaces:
                    lsuAds = []
                    interface.constructLSUAdsForInterface(interface, lsuAds)
                    lsuPacket = interface.constructLSUPacket(lsuAds)
                    self.controller.floodLSU(lsuPacket)
            time.sleep(1)

class ARPTimeouts(Thread):
    def __init__(self, controller, arp_timeout=120):
        super(ARPTimeouts, self).__init__()
        self.controller = controller
        self.arp_timeout = arp_timeout
        self.stop_event = Event()
    
    def run(self):
        while not self.stop_event.is_set():
            for (addr, mac), timestamp in self.controller.arp_entry_log.items():
                if time.time() - timestamp > self.arp_timeout:
                    del self.controller.arp_entry_log[addr]
                    del self.controller.mac_for_ip[addr]
                    del self.controller.port_for_mac[mac]
                    self.controller.sw.removeTableEntry(
                        table_name='MyIngress.arp_table',
                        match_fields={'next_hop_ip_address': addr},
                    )
            time.sleep(1)
                    
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
        Interval between link state link_state_ads
    interfaces : list
        A list of interfaces on the router
    
    '''
    def __init__(self, sw, router, area_id, interfaces, hosts=[], lsuint=10, start_wait=0.3):
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
        self.last_arp = None
        self.arp_entry_log = {}

        self.adjacent_routes = set()

        # ----------- INTERFACES ------------
        self.interfaces = []

        self.DEBUG = True

        self.previous_lsu_packets = {}

        for interface in interfaces:
            self.interfaces.append(Interface(interface["ip"], interface["mask"], interface["helloint"], interface["port"], self))
        
        self.topology_database = {}

        self.current_lsu_sequence = 0
        self.lsu_ticker = LSU(self)
        self.interface_hello_monitor = InterfaceHelloMonitor(self)
        self.arp_timeouts = ARPTimeouts(self)

    def print_counters(self):
        print("Counters for router", self.router_id)
        print("--------------------")
        print("IP packets:")
        print(self.sw.readCounter("IP_packets", 0)[0])
        print("ARP packets:")
        print(self.sw.readCounter("ARP_packets", 0)[0])
        print("CPU_packets")
        print(self.sw.readCounter("CPU_packets", 0)[0])



    def generateSubnet(self, router_id, mask):
        subnet = router_id.split(".")
        mask = mask.split(".")
        subnet = [int(subnet[i]) & int(mask[i]) for i in range(4)]
        return ".".join([str(i) for i in subnet])

    def debug(self, *args):
        if(self.DEBUG):
            print(f"{self.router_id} - DEBUG: ", *args)

    def find_port_to_router(self, router_id):
        for interface in self.interfaces:
            for neighbor in interface.neighbors:
                if neighbor["routerId"] == router_id:
                    return interface.port
        return None

    def findInterfaceByIp(self, ip):
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
    
    def addIpAddr(self, ip, mac):
        # Don't re-add the ip-mac mapping if we already have it:
        if ip in self.mac_for_ip: return
        self.sw.insertTableEntry(table_name='MyIngress.arp_table',
                match_fields={'next_hop_ip_address': ip},
                action_name='MyIngress.arp_hit',
                action_params={'mac': mac})
        self.mac_for_ip[ip] = mac

    def handleArpReply(self, pkt):
        self.addMacAddr(pkt[ARP].hwsrc, pkt[CPUMetadata].srcPort)
        self.addIpAddr(pkt[ARP].psrc, pkt[ARP].hwsrc)
        self.arp_entry_log[(pkt[ARP].psrc, pkt[ARP].hwsrc)] = time.time()
        self.send(pkt)
    
    def _setArpHeaders(self, pkt, matched_interface):
        pkt[ARP].op = ARP_OP_REPLY
        pkt[ARP].hwdst = pkt[ARP].hwsrc
        temp_pdst = pkt[ARP].pdst
        pkt[ARP].pdst = pkt[ARP].psrc
        pkt[ARP].hwsrc = self.mac_addr
        if matched_interface is not None:
            pkt[ARP].psrc = matched_interface.ip
        else:
            pkt[ARP].psrc = temp_pdst
        return pkt

    def _reverseEthernet(self, pkt):
        pkt[Ether].src, pkt[Ether].dst = self.mac_addr, pkt[Ether].src
        return pkt

    def _constructArpReply(self, pkt, matched_interface):
        pkt = self._setArpHeaders(pkt, matched_interface)
        pkt = self._reverseEthernet(pkt)
        return pkt

    def _constructOwnArpReply(self, pkt):
        pkt = self._setArpHeaders(pkt, None)
        pkt = self._reverseEthernet(pkt)
        return pkt

    def handleArpRequest(self, pkt):
        # Ignore ARP requests from the same router
        self.addMacAddr(pkt[ARP].hwsrc, pkt[CPUMetadata].srcPort)
        self.addIpAddr(pkt[ARP].psrc, pkt[ARP].hwsrc) 
        self.arp_entry_log[(pkt[ARP].psrc, pkt[ARP].hwsrc)] = time.time()

        # If the destination IP is one of the router's interfaces, send an ARP reply
        matched_interface = self.findInterfaceByIp(pkt[ARP].pdst)
        if matched_interface is not None:
            pkt = self._constructArpReply(pkt, matched_interface)
            self.send(pkt)
        else:
            if pkt[ARP].pdst == self.last_arp:
                return
            self.last_arp = pkt[ARP].pdst
            self.send(pkt)
    
    def constructLSUAdsForInterface(self, interface, lsuAds):
        for neighbor in interface.neighbors:
            lsuAd = LSUAdvertisement()
            lsuAd.subnet = interface.ip
            lsuAd.routerID = neighbor["routerId"]
            lsuAd.mask = interface.mask
            lsuAds.append(lsuAd)

    def _lsu_ether_encap(self, pkt):
        pkt[Ether].src = self.mac_addr
        pkt[Ether].dst = BCAST_ETHER_ADDR
    
    def _lsu_cpu_encap(self, pkt):
        pkt[CPUMetadata].fromCpu = 1
        pkt[CPUMetadata].origEtherType = 0x0800
        pkt[CPUMetadata].srcPort = 1

    def _lsu_ip_encap(self, pkt, dst_ip, src_ip):
        pkt[IP].src = src_ip
        pkt[IP].dst = dst_ip
   
    def _lsu_PWOSPF_encap(self, pkt):
        pkt[PWOSPFPacket].version = 2
        pkt[PWOSPFPacket].type = OSPF_LSU_TYPE
        pkt[PWOSPFPacket].packet_length = 0
        pkt[PWOSPFPacket].router_id = self.router_id
        pkt[PWOSPFPacket].area_id = self.area_id
        pkt[PWOSPFPacket].checksum = 0
        pkt[PWOSPFPacket].autype = 0
        pkt[PWOSPFPacket].authentication = 0
    
    def _lsu_encap(self, pkt, link_state_ads):
        pkt[LSUPacket].ttl = 64
        pkt[LSUPacket].num_advertisements = len(link_state_ads)
        pkt[LSUPacket].link_state_ads = link_state_ads

    def constructLSUPacket(self, link_state_ads):
        pkt = Ether()/CPUMetadata()/IP()/PWOSPFPacket()/LSUPacket()
        self._lsu_ether_encap(pkt)
        self._lsu_cpu_encap(pkt)
        # IP encap handled in floodLSU
        self._lsu_PWOSPF_encap(pkt)
        self._lsu_encap(pkt, link_state_ads)
        return pkt

    def handleICMPRequest(self, pkt):
        macAddress = self.mac_for_ip.get(pkt[IP].src)   
        respPkt = Ether()/CPUMetadata()/IP()/ICMP()
        respPkt[Ether].src = self.mac_addr
        respPkt[Ether].dst = macAddress
        respPkt[CPUMetadata].fromCpu = 1
        respPkt[CPUMetadata].origEtherType = 0x0800
        respPkt[CPUMetadata].dstPort = 0
        respPkt[CPUMetadata].srcPort = 1
        respPkt[IP].src = pkt[IP].dst
        respPkt[IP].dst = pkt[IP].src
        respPkt[IP].proto = ICMP_PROTOCOL_NUMBER
        respPkt[ICMP].type = 0
        respPkt[ICMP].code = 0
        respPkt[ICMP].id = pkt[ICMP].id
        respPkt[ICMP].seq = pkt[ICMP].seq
        respPkt[ICMP].payload = pkt[ICMP].payload
        self.send(respPkt)
    
    def handleICMPUnreachable(self, pkt):
        respPkt = Ether() / CPUMetadata() / IP() / ICMP()
        respPkt[Ether].dst = pkt[Ether].src
        respPkt[Ether].src = self.mac_addr
        respPkt[CPUMetadata].fromCpu = 1
        respPkt[CPUMetadata].origEtherType = CPU_ORIG_ETHER_TYPE
        respPkt[CPUMetadata].srcPort = 1
        respPkt[CPUMetadata].dstPort = 0
        respPkt[IP].src = pkt[IP].dst
        respPkt[IP].dst = pkt[IP].src
        respPkt[IP].proto = ICMP_PROTOCOL_NUMBER
        respPkt[ICMP].type = ICMP_UNREACHABLE_TYPE
        respPkt[ICMP].code = ICMP_UNREACHABLE_CODE
        self.send(respPkt)


    def floodLSU(self, lsuPacket):
        if lsuPacket.ttl <= 1:
            return

        lsuPacket.ttl -= 1
        for interface in self.interfaces:
            for neighbor in interface.neighbors:
                # Don't flood to the interface that the packet came from
                if neighbor["interfaceIp"] == lsuPacket[IP].src:
                    continue
                lsuPacket[CPUMetadata].dstPort = interface.port
                lsuPacket[LSUPacket].sequence = self.current_lsu_sequence
                self._lsu_ip_encap(lsuPacket, neighbor["interfaceIp"], interface.ip)
                self.send(lsuPacket)

        self.current_lsu_sequence += 1

    def __str__(self):
        print(f"Router ID: {self.router_id} Area ID: {self.area_id} LSUInt: {self.lsuint} Interfaces: {self.interfaces} Adjacency List: {self.adjacency_list}")

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
    def _PWOSPFPacketisValid(self, pkt):
        if pkt[PWOSPFPacket].version != 2:
            return False

        if pkt[PWOSPFPacket].area_id != self.area_id:
            return False
        
        if pkt[PWOSPFPacket].autype != 0:
            return False    

        return True

    def _HelloPacketisValid(self, interface, pkt):
        return pkt[HelloPacket].network_mask == interface.mask or pkt[HelloPacket].hello_int == interface.helloint

    def findInterfaceByPort(self, port):
        for interface in self.interfaces:
            if interface.port == port:
                return interface
        return None

    def findInterfaceForRouterId(self, routerId):
        for interface in self.interfaces:
            for neighbor in interface.neighbors:
                if neighbor["routerId"] == routerId:
                    return interface
        return None

    def findIpForInterfaceFromRouterId(self, routerId):
        for interface in self.interfaces:
            for neighbor in interface.neighbors:
                if neighbor["routerId"] == routerId:
                    return neighbor["interfaceIp"]
        return None

    
    def handleHelloPacket(self, pkt):
        # Drop packets from the same router
        if pkt[PWOSPFPacket].router_id == self.router_id:
            return

        interface = self.findInterfaceByPort(pkt[CPUMetadata].srcPort)

        if interface == None or not self._HelloPacketisValid(interface, pkt):
            return 

        neighbor = neighborFactory(pkt[PWOSPFPacket].router_id, pkt[IP].src)
        interface.handleNeighbor(neighbor)
        self.addIpAddr(pkt[IP].src, pkt[Ether].src)
        self.addMacAddr(pkt[Ether].src, pkt[CPUMetadata].srcPort)

    def shouldAddEntry(self, entry, query):
        should_add = True
        for item in self.topology_database[query]:
            if item["routerId"] == entry["routerId"]:
                should_add = False
                break
        return should_add and entry not in self.topology_database[query]

    def updateTopologyDatabase(self, pkt):
        source = pkt[PWOSPFPacket].router_id

        if source not in self.topology_database:
            self.topology_database[source] = []
        
        new_changes = False

        for ad in pkt[LSUPacket].link_state_ads:
            destination = ad.routerID
            if destination not in self.topology_database:
                self.topology_database[destination] = []

            destination_database_entry = {
                "routerId": ad.routerID,
            }

            source_database_entry = {
                "routerId": source,
            }

            # Check if the database entry already exists
            if self.shouldAddEntry(destination_database_entry, source):
                new_changes = True
                self.topology_database[source].append(destination_database_entry)
            
            if self.shouldAddEntry(source_database_entry, destination):
                new_changes = True
                self.topology_database[destination].append(source_database_entry)
        
        return new_changes

    def build_graph(self):
        graph = defaultdict(dict)
        for router, connections in self.topology_database.items():
            for connection in connections:
                neighbor = connection["routerId"]
                graph[router][neighbor] = 1  # Assuming uniform cost of links
        return graph

    def dijkstra(self, start):
        distances = {vertex: float('infinity') for vertex in self.topology_database}
        previous_nodes = {vertex: None for vertex in self.topology_database}
        distances[start] = 0
        pq = [(0, start)]  

        while pq:
            current_distance, current_vertex = heappop(pq)
            if current_vertex not in self.topology_database:
                continue
            for neighbor in self.topology_database[current_vertex]:
                router_id = neighbor["routerId"]
                distance = current_distance + 1  

                if distance < distances[router_id]:
                    distances[router_id] = distance
                    previous_nodes[router_id] = current_vertex
                    heappush(pq, (distance, router_id))
        return previous_nodes

    def recomputeRoutes(self):
        previous_nodes = self.dijkstra(self.router_id)
        for destination, prev_node in previous_nodes.items():
            if destination == self.router_id or prev_node is None:
                continue  # Skip the router itself and unreachable nodes
            
            # Get the next_hop for the destination
            current_node = destination
            while previous_nodes[current_node] != self.router_id:
                current_node = previous_nodes[current_node]
            # Find the outgoing interface IP and port for the next_hop (current_node)
            next_hop_ip = self.findIpForInterfaceFromRouterId(current_node)
            next_hop_interface = self.findInterfaceForRouterId(current_node)

            if next_hop_interface is None or next_hop_ip is None:
                return

            entry = self.generateSubnet(destination, next_hop_interface.mask)

            if destination in self.adjacent_routes:
                self.sw.removeTableEntry(
                    table_name='MyIngress.routing_table',
                    match_fields={'hdr.ipv4.dstAddr': [entry, 24]}
                )

            # Insert the routing table entry
            self.sw.insertTableEntry(
                table_name='MyIngress.routing_table',
                match_fields={'hdr.ipv4.dstAddr': [entry, 24]},
                action_name='MyIngress.ip_hit',
                action_params={'next_hop': next_hop_ip, 'port': next_hop_interface.port}
            )

            # Add the destination to the adjacent routes
            self.adjacent_routes.add(destination)

    def handleLSUPacket(self, pkt):
        routerId = pkt[PWOSPFPacket].router_id

        if routerId == self.router_id:
            return
        
        if pkt[LSUPacket].link_state_ads == None or len(pkt[LSUPacket].link_state_ads) == 0:
            return
        
        should_recompute_routes = True
        if routerId in self.previous_lsu_packets:
            # Check if the packet is older than the previous packet
            previous_packet_sequence = self.previous_lsu_packets[routerId].sequence
            if pkt[LSUPacket].sequence <= previous_packet_sequence:
                return
            if pkt[LSUPacket].link_state_ads == self.previous_lsu_packets[routerId].link_state_ads:
                should_recompute_routes = False
        else:
            should_recompute_routes = self.updateTopologyDatabase(pkt)
        
        if should_recompute_routes:
            self.recomputeRoutes()
        
        self.previous_lsu_packets[routerId] = pkt
        self.floodLSU(pkt)

    def handlePkt(self, pkt):
        # Ignore packets without CPU metadata
        if CPUMetadata not in pkt:
            return
        
        # Ignore packets that the CPU sends:
        if pkt[CPUMetadata].fromCpu == 1: 
           return
        
        if ARP in pkt:
            if pkt[ARP].op == ARP_OP_REQ:
                # pkt.show()
                self.handleArpRequest(pkt)
            elif pkt[ARP].op == ARP_OP_REPLY:
                self.handleArpReply(pkt)
        
        if ICMP in pkt:
            self.handleICMPRequest(pkt)
        
        if IP in pkt:
            # Check to see if the packet is for any of the interfaces it owns
            unreachable = True
            for interface in self.interfaces:
                if pkt[IP].dst == interface.ip or pkt[IP].dst == BCAST_HELLO_IP_ADDR:
                    unreachable = False
                    break
            
            if unreachable:
                self.handleICMPUnreachable(pkt)

        if PWOSPFPacket in pkt:
            if not self._PWOSPFPacketisValid(pkt):
                return

            if HelloPacket in pkt:
                self.handleHelloPacket(pkt)

            if LSUPacket in pkt:
                self.handleLSUPacket(pkt)

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
            interface.start()
        
        self.lsu_ticker.start()
        self.interface_hello_monitor.start()
        self.arp_timeouts.start()

    def join(self, *args, **kwargs):
        self.stop_event.set()
        super(Controller, self).join(*args, **kwargs)
