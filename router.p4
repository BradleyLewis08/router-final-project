/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

typedef bit<9>  port_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<16> mcastGrp_t;

const port_t CPU_PORT           = 0x1;

const bit<16> ARP_OP_REQ        = 0x0001;
const bit<16> ARP_OP_REPLY      = 0x0002;

const bit<16> TYPE_IPV4         = 0x0800;
const bit<16> TYPE_ARP          = 0x0806;
const bit<16> TYPE_CPU_METADATA = 0x080a;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header cpu_metadata_t {
    bit<8> fromCpu;
    bit<16> origEtherType;
    bit<16> srcPort;
    bit<16> dstPort;
}

header arp_t {
    bit<16> hwType;
    bit<16> protoType;
    bit<8> hwAddrLen;
    bit<8> protoAddrLen;
    bit<16> opcode;
    macAddr_t srcEth;
    ip4Addr_t srcIP;
    macAddr_t dstEth;
    ip4Addr_t dstIP;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

struct headers {
    ethernet_t        ethernet;
    cpu_metadata_t    cpu_metadata;
    arp_t             arp;
    ipv4_t            ipv4;
}

struct metadata { }

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_ARP: parse_arp;
            TYPE_CPU_METADATA: parse_cpu_metadata;
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_cpu_metadata {
        packet.extract(hdr.cpu_metadata);
        transition select(hdr.cpu_metadata.origEtherType) {
            TYPE_ARP: parse_arp;
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    ip4Addr_t next_hop_ip_address = 0;
    macAddr_t next_hop_mac_address = 0;
    bit<16> cpu_bound = 0;

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action set_egr(port_t port) {
        standard_metadata.egress_spec = port;
    }

    action set_mgid(mcastGrp_t mgid) {
        standard_metadata.mcast_grp = mgid;
    }

    // ------------------------ CPU Processing ------------------------

    action cpu_meta_encap() {
        hdr.cpu_metadata.setValid();
        hdr.cpu_metadata.origEtherType = hdr.ethernet.etherType;
        hdr.cpu_metadata.srcPort = (bit<16>)standard_metadata.ingress_port;
        hdr.ethernet.etherType = TYPE_CPU_METADATA;
    }

    action cpu_meta_decap() {
        hdr.ethernet.etherType = hdr.cpu_metadata.origEtherType;
        hdr.cpu_metadata.setInvalid();
    }

    action send_to_cpu() {
        cpu_meta_encap();
        standard_metadata.egress_spec = CPU_PORT;
    }

    // ------------------------ ARP Processing ------------------------

    action arp_hit(macAddr_t mac) {
        // Update the destination MAC address
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = mac;
    }

    action ip_hit(port_t port, ip4Addr_t next_hop) {
        set_egr(port);
        next_hop_ip_address = next_hop;
    }

    table fwd_l2 {
        key = {
            hdr.ethernet.dstAddr: exact;
        }
        actions = {
            set_egr;
            set_mgid;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    table arp_table {
        key={
            next_hop_ip_address: exact;
        }
        actions={
            arp_hit;
            NoAction;
        }
        size=64;
        default_action = NoAction;
    }

    table routing_table {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ip_hit;
            send_to_cpu; // If no match in the routing table, send to CPU
        }
    }

    // For local forwarding
    table local_forwarding_table {
        key = {
            hdr.ipv4.dstAddr: exact;
        }
        actions = {
            ip_hit;
            send_to_cpu;
        }
    }

    table debug_table {
        key = {
            // Log all packet details
            hdr.ethernet.dstAddr: exact;
            hdr.ethernet.srcAddr: exact;
            hdr.ethernet.etherType: exact;
            hdr.arp.hwType: exact;
            hdr.arp.protoType: exact;
            hdr.arp.hwAddrLen: exact;
            hdr.arp.protoAddrLen: exact;
            hdr.arp.opcode: exact;
            hdr.arp.srcEth: exact;
            hdr.arp.srcIP: exact;
            hdr.arp.dstEth: exact;
            hdr.arp.dstIP: exact;
            hdr.ipv4.srcAddr: exact;
            hdr.ipv4.dstAddr: exact;
            hdr.ipv4.protocol: exact;
            standard_metadata.ingress_port: exact;
            standard_metadata.egress_spec: exact;
            next_hop_ip_address: exact;
            next_hop_mac_address: exact;
            cpu_bound: exact;
        }
        actions = {
            NoAction;
        }
        size = 64;
        default_action = NoAction;
    }

    bit<16> dstPortSet = 0;

    apply {
        if (standard_metadata.ingress_port == CPU_PORT) {
            if(hdr.cpu_metadata.isValid() && hdr.cpu_metadata.dstPort != 0) {
                standard_metadata.egress_spec = (bit<9>)hdr.cpu_metadata.dstPort;
                dstPortSet = 1;
            }
            cpu_meta_decap();
        }

        debug_table.apply();

        if(dstPortSet != 1) { // If routing information did not come from CPU
            if (hdr.arp.isValid() && standard_metadata.ingress_port != CPU_PORT) {
                send_to_cpu();
            } else if (hdr.ipv4.isValid() && dstPortSet != 1) { // Only if CPU did not set the egress port already
                // Handle TTL expiration
                if (hdr.ipv4.ttl == 0) {
                    drop(); 
                } else {
                    hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
                }
                
                // Set the next_hop_ip address by looking either locally or in the routing table.
                // Sets the next_hop_ip_address and the egress port
                if(!local_forwarding_table.apply().hit) {
                    routing_table.apply();
                } 

                if (standard_metadata.egress_spec != CPU_PORT) {
                    if (!arp_table.apply().hit) {
                        send_to_cpu();
                    }
                }
                // Based on next_hop_ip_address, if we are not sending to CPU, we need to do ARP lookup
            } else if (hdr.ethernet.isValid()) {
                fwd_l2.apply();
            } else {
                send_to_cpu(); // Forward all other packets to CPU for handling
            } 
        }
    }
}

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );
    }
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.cpu_metadata);
        packet.emit(hdr.arp);
        packet.emit(hdr.ipv4);
    }
}

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;