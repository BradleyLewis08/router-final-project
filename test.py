from scapy.all import *

class LSUAdvertisement(Packet):
	name = "LSUAdvertisement"
	fields_desc = [
		IPField("subnet", "0.0.0.0"),
		IPField('mask', "255.255.255.0"),
		IPField('routerID', "0.0.0.0")
	]
	
	def extract_padding(self, s):
		return '', s

class LSUPacket(Packet):
	name = "LSUPacket"
	fields_desc = [
		ShortField("sequence", 0),
		ShortField("ttl", 64),
		FieldLenField("num_advertisements", None, fmt="I", count_of="link_state_ads"),
		PacketListField("link_state_ads", [], LSUAdvertisement, length_from=lambda pkt: pkt.num_advertisements * 12) # assuming each LSUAdvertisement is 12 bytes long
	]

# Test serialization and parsing
def test_packet():
	ad1 = LSUAdvertisement(subnet="192.168.1.0", mask="255.255.255.0", routerID="192.168.1.1")
	ad2 = LSUAdvertisement(subnet="192.168.2.0", mask="255.255.255.0", routerID="192.168.2.1")
	packet = LSUPacket(sequence=1, link_state_ads=[ad1, ad2])
	packet.num_advertisements = len(packet.link_state_ads)

	packet.show()
	print("\nHexdump of packet:")
	hexdump(packet)

	# Serialize and parse the packet
	raw = bytes(packet)
	parsed_packet = LSUPacket(raw)

	print("\nParsed Packet:")
	parsed_packet.show()

test_packet()
