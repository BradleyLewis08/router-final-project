from scapy.fields import IntField, ByteField, ShortField, LongField, IPField, PacketListField
from scapy.packet import Packet, bind_layers
from scapy.layers.inet import IP

TYPE_HELLO = 0x01
TYPE_LSU = 0x04

'''
PWOSPF Packet Structure:

0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Version #   |     Type      |         Packet length         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          Router ID                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Area ID                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Checksum            |             Autype            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Authentication                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Authentication                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Fields
------
	Version #
		The PWOSPF/OSPF version number.  This specification documents version 2 of
		the protocol.

	Type
		The OSPF packet types are as follows.  The format of each of these
		packet types is described in a succeeding section.

		Type   Description
		________________________________
		1      Hello
		4      Link State Update

	Packet length
		The length of the protocol packet in bytes.  This length includes
		the standard OSPF header.

	Router ID
		The Router ID of the packet's source.  In OSPF, the source and
		destination of a routing protocol packet are the two ends of an
		(potential) adjacency.

	Area ID
		A 32 bit number identifying the area that this packet belongs to.
		All OSPF packets are associated with a single area.  Most travel a
		single hop only.

	Checksum
		The standard IP checksum of the entire contents of the packet,
		excluding the 64-bit authentication field.  This checksum is
		calculated as the 16-bit one's complement of the one's complement
		sum of all the 16-bit words in the packet, excepting the
		authentication field.  If the packet's length is not an integral
		number of 16-bit words, the packet is padded with a byte of zero
		before checksumming.

	AuType
	Set to zero in PWOSPF

	Authentication
	Set to zero in PWOSPF
'''

class PWOSPFPacket(Packet):
	name="PWOSPFPacket"
	fields_desc = [
		ByteField("version", 2),
		ByteField("type", 0),
		ShortField("packet_length", None),
		IPField("router_id", None),
		IntField("area_id", None),
		ShortField("checksum", None),
		ShortField("autype", None),
		LongField("authentication", None),
	]

'''
HelloPacket Structure
----------------

0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Version #   |       1       |         Packet length         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          Router ID                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Area ID                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Checksum            |             Autype            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Authentication                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Authentication                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Network Mask                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         HelloInt              |           padding             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Fields
------

Network mask
	The network mask associated with this interface.  For example, if
	the interface is to a class B network whose third byte is used for
	subnetting, the network mask is 0xffffff00.

  HelloInt
	The number of seconds between this router's Hello packets
'''
class HelloPacket(Packet):
	name="HelloPacket"
	fields_desc = [
		IPField("network_mask", None),
		ShortField("hello_int", None),
		ShortField("padding", None)
	]

'''
LSUAdvertisement Structure
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Subnet                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Mask                                |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Router ID                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Fields
------

   Subnet
      Subnet number of the advertised route.  Note that default routes
      will have a subnet value of 0.0.0.0.

   Mask
      Subnet mask of the advertised route

   Router ID
      ID of the neighboring router on the advertised link.  If there is no
      connected router to the link the RID should be set to 0.

'''
class LSUAdvertisement(Packet):
	name="LSUAdvertisement",
	fields_desc = [
		IPField("subnet", "0.0.0.0"),
		IPField('mask', None),
		IPField('routerID', None)
	]

'''
LSU Packet Structure
----------------
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Version #   |       4       |         Packet length         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          Router ID                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Area ID                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Checksum            |             Autype            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Authentication                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Authentication                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Sequence                |          TTL                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      # advertisements                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+-                                                            +-+
|                  Link state advertisements                    |
+-                                                            +-+
|                              ...                              |

Fields
------

Sequence
     Unique sequence number associated with each Link State Updated.
     Incremented by the LSU source for each subsequence updated.  Duplicate
     LSU packets are dropped by the receiver.

  TTL
     Hop limited value decremented each time the packet is forwarded.  The
     TTL value is only considered during packet forwarding and not during
     packet reception.

  # advertisements
     Total number of link state advertisements contained in the packet


'''

class LSUPacket(Packet):
	name="LSUPacket"
	fields_desc = [
		IPField("sequence", None),
		IPField("ttl", None),
		IPField("num_advertisements", None),
		PacketListField("link_state_ads", None, LSUAdvertisement, length_from=lambda pkt:pkt.num_advertisements)
	]


# PWOSPF are expected to be encapsulated IPv4 packets with IP protocol number 89 
bind_layers(IP, PWOSPFPacket, proto=89)
bind_layers(PWOSPFPacket, HelloPacket, type=TYPE_HELLO)		
bind_layers(PWOSPFPacket, LSUPacket, type=TYPE_LSU)



