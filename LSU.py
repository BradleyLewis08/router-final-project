from threading import Thread
import time
from packets import *
from constants import *
from cpu_metadata import CPUMetadata
from scapy.all import Ether, IP

class LSU(Thread):
	def __init__(self, router):
		super(LSU, self).__init__()
		self.router = router

	def constructLSUAdsForInterface(self, interface, lsuAds):
		for neighbor in interface.neighbors:
			lsuAd = LSUAdvertisement()
			lsuAd.subnet = self.router.generateSubnet(neighbor["routerId"], interface.mask)
			lsuAd.routerID = neighbor["routerId"]
			lsuAd.mask = interface.mask
			lsuAds.append(lsuAd)

	def _lsu_ether_encap(self, pkt):
		pkt[Ether].src = self.router.mac_addr
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
		pkt[PWOSPFPacket].router_id = self.router.router_id
		pkt[PWOSPFPacket].area_id = self.router.area_id
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
	
	def run(self):
		while True:
			time.sleep(self.router.lsuint)
			lsuAds = []
			for interface in self.router.interfaces:
				self.constructLSUAdsForInterface(interface, lsuAds)
			lsuPacket = self.constructLSUPacket(lsuAds)
			self.router.floodLSU(lsuPacket, False)

