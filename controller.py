
from heapq import heappop, heappush
from collections import defaultdict
from threading import Thread, Event
from scapy.all import sendp
from scapy.all import Packet, Ether, IP, ARP, ICMP
from async_sniff import sniff
from cpu_metadata import CPUMetadata
from packets import PWOSPFPacket, HelloPacket, LSUPacket, LSUAdvertisement

import time
import json


from constants import *
from interface import Interface, neighborFactory

class LSUTicker(Thread):
    def __init__(self, controller, lsuint):
        super(LSUTicker, self).__init__()
        self.controller = controller
        self.lsuint = lsuint
    
    def run(self):
        while True:
            self.controller.startLSUTick()
            time.sleep(self.lsuint)

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
    def __init__(self, sw, router, area_id, interfaces, hosts=[], lsuint=2, start_wait=0.3):
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

        self.DEBUG = False

        self.previous_packet_sequence_nums = {}

        for interface in interfaces:
            self.interfaces.append(Interface(interface["ip"], interface["mask"], interface["helloint"], interface["port"], self))
        
        self.topology_database = {}
        self.hosts = hosts

        self.current_lsu_sequence = 0
        # Start the startLSUTick thread
    
    def print_topology_database(self):
        print(f"Topology Database for router {self.router_id}:")
        print(json.dumps(self.topology_database, indent=4))

    # Debug statement that can take a string and argument
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
        self.addMacAddr(pkt[ARP].hwsrc, pkt[CPUMetadata].srcPort)
        self.addIpAddr(pkt[ARP].psrc, pkt[ARP].hwsrc) 

        # If the destination IP is one of the router's interfaces, send an ARP reply
        matched_interface = self.findInterfaceByIp(pkt[ARP].pdst)

        if matched_interface is not None:
            pkt = self._constructArpReply(pkt, matched_interface)
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

    def _lsu_ip_encap(self, pkt, dst_ip):
        pkt[IP].src = self.router_id
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
    
    def _lsu_encap(self, pkt, advertisements):
        pkt[LSUPacket].ttl = 64
        pkt[LSUPacket].num_advertisements = len(advertisements)
        pkt[LSUPacket].link_state_ads = advertisements

    def constructLSUPacket(self, advertisements):
        pkt = Ether()/CPUMetadata()/IP()/PWOSPFPacket()/LSUPacket()
        self._lsu_ether_encap(pkt)
        self._lsu_cpu_encap(pkt)
        # IP encap handled in floodLSU
        self._lsu_PWOSPF_encap(pkt)
        self._lsu_encap(pkt, advertisements)
        return pkt

    def startLSUTick(self):
        while True:
            lsuAds = []
            for interface in self.interfaces:
                self.constructLSUAdsForInterface(interface, lsuAds)
            lsuPacket = self.constructLSUPacket(lsuAds)
            self.floodLSU(lsuPacket)

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
                self._lsu_ip_encap(lsuPacket, neighbor["interfaceIp"])
                self.send(lsuPacket)

        self.current_lsu_sequence += 1

    def handleICMP(self, pkt):
        respPkt = Ether()/CPUMetadata()/IP()/ICMP()
        respPkt[CPUMetadata].fromCpu = 1
        respPkt[CPUMetadata].origEtherType = 0x0800
        respPkt[CPUMetadata].srcPort = 1
        # Swap the source and destination IP addresses
        respPkt[IP].src = pkt[IP].dst
        respPkt[IP].dst = pkt[IP].src
        respPkt[IP].proto = 0x01
        respPkt[ICMP].type = 0
        respPkt[ICMP].code = 0
        respPkt[ICMP].id = pkt[ICMP].id
        respPkt[ICMP].seq = pkt[ICMP].seq
        self.send(respPkt)
    
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
        # Check 1
        if pkt[PWOSPFPacket].version != 2:
            return False

        # TODO: Check 2

        # Check 3
        if pkt[PWOSPFPacket].area_id != self.area_id:
            return False
        
        # Check 4
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
    
    def handleHelloPacket(self, pkt):
        # Drop packets from the same router
        if pkt[PWOSPFPacket].router_id == self.router_id:
            return

        interface = self.findInterfaceByPort(pkt[CPUMetadata].srcPort)

        if interface == None or not self._HelloPacketisValid(interface, pkt):
            return 

        neighbor = neighborFactory(pkt[PWOSPFPacket].router_id, pkt[IP].src)
        interface.handleNeighbor(neighbor)

    def _LSUPacketisValid(self, pkt):
        routerId = pkt[PWOSPFPacket].router_id
        if routerId == self.router_id:
            return False
        
        if pkt[LSUPacket].link_state_ads == None or len(pkt[LSUPacket].link_state_ads) == 0:
            return False

        if routerId in self.previous_packet_sequence_nums:
            previous_packet_sequence = self.previous_packets[routerId]
            if pkt[LSUPacket].sequence <= previous_packet_sequence:
                return False
            self.previous_packet_sequence_nums[routerId] = pkt[LSUPacket].sequence
        
        return True

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
        
        for ad in pkt[LSUPacket].link_state_ads:
            destination = ad.routerID
            if destination not in self.topology_database:
                self.topology_database[destination] = []

            destination_database_entry = {
                "subnet": ad.subnet,
                "routerId": ad.routerID,
                "mask": ad.mask
            }

            source_database_entry = {
                "subnet": ad.subnet,
                "routerId": source,
                "mask": ad.mask
            }

            # Check if the database entry already exists
            if self.shouldAddEntry(destination_database_entry, source):
                self.topology_database[source].append(destination_database_entry)
            
            if self.shouldAddEntry(source_database_entry, destination):
                self.topology_database[destination].append(source_database_entry)

    def build_graph(self):
        graph = defaultdict(dict)
        for router, connections in self.topology_database.items():
            for connection in connections:
                neighbor = connection["routerId"]
                graph[router][neighbor] = 1  # Assuming uniform cost of links
        return graph

    def dijkstra(graph, start):
        distances = {vertex: float('infinity') for vertex in graph}
        previous_nodes = {vertex: None for vertex in graph}
        distances[start] = 0
        pq = [(0, start)]  

        while pq:
            current_distance, current_vertex = heappop(pq)
            for neighbor in graph[current_vertex]:
                distance = current_distance + graph[current_vertex][neighbor]
                if distance < distances[neighbor]:
                    distances[neighbor] = distance
                    previous_nodes[neighbor] = current_vertex
                    heappush(pq, (distance, neighbor))
        return distances, previous_nodes

    def build_routing_table_for_router(self, graph, start):
        distances, previous_nodes = dijkstra(graph, start)
        routing_table = {}
        for destination, path_cost in distances.items():
            if destination == start:
                continue
            
            next_hop = destination
            while previous_nodes[next_hop] != start:
                next_hop = previous_nodes[next_hop]
            
            for connection in self.topology_database[start]:
                if connection["routerId"] == destination:
                    subnet = connection["subnet"]
                    mask = connection["mask"]
                    routing_table[destination] = {
                        'next_hop': next_hop,
                        'cost': path_cost,
                        'subnet': subnet,
                        'mask': mask
                    }
                    break

        return routing_table
 
    def recomputeRoutes(self):
        graph = self.build_graph()
        routing_table = self.build_routing_table_for_router(graph, self.router_id)
        for neighbor, routing_info in routing_table.items():
            port = self.find_port_to_router(neighbor)
            if port is None:
                continue
            self.sw.insertTableEntry(table_name='MyIngress.ipv4_lpm',
                match_fields={'hdr.ipv4.dstAddr': [routing_info['subnet'], routing_info['mask']]},
                action_name='MyIngress.ipv4_forward',
                action_params={'dstAddr': routing_info['next_hop'], 'port': port})


    def handleLSUPacket(self, pkt):
        if not self._LSUPacketisValid(pkt): # Drop invalid packets
            return
        
        # Check if the packet has been seen before
        self.updateTopologyDatabase(pkt)
        # self.recomputeRoutes()
        self.floodLSU(pkt)
        return

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
            self.debug("Received ICMP packet")
            self.handleICMP(pkt)

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
        
        lsu_thread = Thread(target=self.startLSUTick)
        lsu_thread.start()

    def join(self, *args, **kwargs):
        self.stop_event.set()
        super(Controller, self).join(*args, **kwargs)
