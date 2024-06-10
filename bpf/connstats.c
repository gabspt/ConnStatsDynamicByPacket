#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct packet_t {
    struct in6_addr src_ip;
    struct in6_addr dst_ip;
    __be16 src_port;
    __be16 dst_port;
    __u8 protocol;
    bool syn;
    bool ack;
    bool fin;
    bool rst;
    uint64_t ts;
    bool outbound;
    __u32 len;
};
struct __attribute__((packed)) flow_id {
    struct in6_addr l_ip;
    struct in6_addr r_ip;
    __be16 l_port;
    __be16 r_port;
    __u8 protocol;
};
struct flow_metrics {
    __u32 packets_in;
    __u32 packets_out;
    __u64 bytes_in;
    __u64 bytes_out;
    __u64 ts_start;
    __u64 ts_current;
    //__u8 fin_counter;
    bool flow_closed;
    bool syn_or_udp_to_rb;
};

struct flow_record {
    struct flow_id id;  
    struct flow_metrics metrics;
};

struct global_metrics {
    __u64 total_packets;
    __u64 total_tcppackets;
    __u64 total_udppackets;
    //__u64 total_bytes;
    __u64 total_flows;
    __u64 total_tcpflows;
    __u64 total_udpflows;
};

// struct flow_stats {
//     struct flow_id id;
//     __u32 inpps;
//     __u64 outpps;
//     __u64 inBpp;
//     __u64 outBpp;
//     __u64 inBoutB;
//     __u64 onPoutP;
// };

bool syndidntfitsentrb = false;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    //__uint(max_entries, 512 * 1024); // 512 KB
    __uint(max_entries, 1 << 24);    
} pipe SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1 << 24);
    __type(key, struct flow_id);
    __type(value, struct flow_metrics);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} flowstracker SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1 );
    __type(key, __u32);
    __type(value, struct global_metrics); // cambiar por una nueva struct que contenga las metricas glbaes
} globalmetrics SEC(".maps");

static inline int handle_ip_packet(uint8_t* head, uint8_t* tail, uint32_t* offset, struct packet_t* pkt) {
    struct ethhdr* eth = (void*)head;
    struct iphdr* ip;
    struct ipv6hdr* ipv6;

    switch (bpf_ntohs(eth->h_proto)) {
    case ETH_P_IP:
        *offset = sizeof(struct ethhdr) + sizeof(struct iphdr);

        if (head + (*offset) > tail) { // If the next layer is not IP, let the packet pass
            return TC_ACT_OK;
        }

        ip = (void*)head + sizeof(struct ethhdr);

        if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP) {
            return TC_ACT_OK;
        }

        // Create IPv4-Mapped IPv6 Address
        pkt->src_ip.in6_u.u6_addr32[3] = ip->saddr;
        pkt->dst_ip.in6_u.u6_addr32[3] = ip->daddr;

        // Pad the field before IP address with all Fs just like the RFC
        pkt->src_ip.in6_u.u6_addr16[5] = 0xffff;
        pkt->dst_ip.in6_u.u6_addr16[5] = 0xffff;

        pkt->protocol = ip->protocol;

        return 1; // We have a TCP or UDP packet!

    case ETH_P_IPV6:
        *offset = sizeof(struct ethhdr) + sizeof(struct ipv6hdr);

        if (head + (*offset) > tail) {
            return TC_ACT_OK;
        }

        ipv6 = (void*)head + sizeof(struct ethhdr);

        if (ipv6->nexthdr != IPPROTO_TCP && ipv6->nexthdr != IPPROTO_UDP) {
            return TC_ACT_OK;
        }

        pkt->src_ip = ipv6->saddr;
        pkt->dst_ip = ipv6->daddr;

        pkt->protocol = ipv6->nexthdr;

        return 1; // We have a TCP or UDP packet!

    default:
        return TC_ACT_OK;
    }
}

static inline int handle_ip_segment(uint8_t* head, uint8_t* tail, uint32_t* offset, struct packet_t* pkt) {
    struct tcphdr* tcp;
    struct udphdr* udp;

    switch (pkt->protocol) {
    case IPPROTO_TCP:
        tcp = (void*)head + *offset;

        pkt->src_port = tcp->source;
        pkt->dst_port = tcp->dest;
        pkt->syn = tcp->syn;
        pkt->ack = tcp->ack;
        pkt->fin = tcp->fin;
        pkt->rst = tcp->rst;
        pkt->ts = bpf_ktime_get_ns();

        return 1;

    case IPPROTO_UDP:
        udp = (void*)head + *offset;

        pkt->src_port = udp->source;
        pkt->dst_port = udp->dest;
        pkt->ts = bpf_ktime_get_ns();

        return 1;

    default:
        return TC_ACT_OK;
    }
}

static inline int submit_flow_record(struct flow_id flowid, struct flow_metrics flowmetrics) {
    struct flow_record *record = (struct flow_record *)bpf_ringbuf_reserve(&pipe, sizeof(struct flow_record), 0);
    if (!record) {
        return TC_ACT_OK;
    }
    record->id = flowid;
    record->metrics = flowmetrics;
    bpf_ringbuf_submit(record, 0);
    return 0;
}

static inline int update_metrics(struct packet_t* pkt) {
    //update global metrics total_packets, total_tcp_packets, total_udp_packets 
    __u32 keygb = 0;
    struct global_metrics *globalm = bpf_map_lookup_elem(&globalmetrics, &keygb);
    if (!globalm) {
        struct global_metrics new_globalm = {0};
        new_globalm.total_packets = 1; //probar modificarlo fuera 
        new_globalm.total_tcppackets = (pkt->protocol == IPPROTO_TCP) ? 1 : 0;
        new_globalm.total_udppackets = (pkt->protocol == IPPROTO_TCP) ? 0 : 1;
        bpf_map_update_elem(&globalmetrics, &keygb, &new_globalm, BPF_ANY);
        globalm = &new_globalm;
    } else {
        globalm->total_packets += 1;
        if (pkt->protocol == IPPROTO_TCP) {
            globalm->total_tcppackets += 1;
        } else {
            globalm->total_udppackets += 1;
        }
        bpf_map_update_elem(&globalmetrics, &keygb, globalm, BPF_ANY); 
    }

    //conformando el flow id
    struct flow_id flowid = {0};
    flowid.protocol = pkt->protocol;
    if (pkt->outbound == true) { // outbound egress flow
        flowid.l_ip = pkt->src_ip;
        flowid.r_ip = pkt->dst_ip;
        flowid.l_port = pkt->src_port;
        flowid.r_port = pkt->dst_port;
    } 
    else { // inbound ingress flow
        flowid.l_ip = pkt->dst_ip;
        flowid.r_ip = pkt->src_ip;
        flowid.l_port = pkt->dst_port;
        flowid.r_port = pkt->src_port;
    }

    struct flow_metrics *flowmetrics = bpf_map_lookup_elem(&flowstracker, &flowid);
    if (flowmetrics != NULL) {
        //flow exists -> update metrics
        flowmetrics->ts_current = pkt->ts;
        if (pkt->outbound == true) { //update outbound egress metrics
            flowmetrics->packets_out += 1;
            flowmetrics->bytes_out += pkt->len;
        } else { //update inbound ingress metrics
            flowmetrics->packets_in += 1;
            flowmetrics->bytes_in += pkt->len;
        }
        // if (pkt->fin == true) {
        //     flowmetrics->fin_counter += 1;
        // }

        //check if flow ended
        //after 2 fin packets and 1 ack are received consider flow ended normally, or if rst packet recieved consider flow ended anormally, -> delete flow from map
        // if ((flowmetrics->fin_counter>=2 && pkt->fin == false && pkt->ack == true) || pkt->rst == true ) {
        //     //consider flow ended, send to userspace to be deleted from hash map and flowtable
        //     flowmetrics->flow_closed = 1;
        //     if (submit_flow_record(flowid, *flowmetrics) == TC_ACT_OK) {
        //         return TC_ACT_OK;
        //     }
        //     //return TC_ACT_OK;
        // }

        //flow considered ended when the FIN/ACK or RST segment are observed
        if ((pkt->fin == true && pkt->ack == true) || pkt->rst == true ) {
            //consider flow ended, send to userspace to be deleted from hash map and flowtable
            flowmetrics->flow_closed = 1;
            if (submit_flow_record(flowid, *flowmetrics) == TC_ACT_OK) {
                return TC_ACT_OK;
            }
            //return TC_ACT_OK;
        }

        long ret = bpf_map_update_elem(&flowstracker, &flowid, flowmetrics, BPF_EXIST);
        if (ret != 0) {
            bpf_printk("error updating flow %d\n", ret);
            return TC_ACT_OK;
        }

    } else {
        //flow doesn't exist, create new flow
        struct flow_metrics new_flowm = {0};
        new_flowm.ts_start = pkt->ts;    
        new_flowm.ts_current = pkt->ts;
        if (pkt->outbound == true) { //update outbound egress metrics
            new_flowm.packets_out = 1;
            new_flowm.bytes_out = pkt->len;
        } else { //update inbound ingress metrics
            new_flowm.packets_in = 1;
            new_flowm.bytes_in = pkt->len;
        }
        if ((pkt->syn == true && pkt->ack == false) || (pkt->protocol == IPPROTO_UDP)) { //new tcp syn or udp connection, add to flowstracker map
        
            //update total flows global metrics
            globalm->total_flows += 1;
            if (pkt->protocol == IPPROTO_TCP) {
                globalm->total_tcpflows += 1;
            } else {
                globalm->total_udpflows += 1;
            }
            bpf_map_update_elem(&globalmetrics, &keygb, globalm, BPF_ANY); 

            //add to flowstracker hash map
            long ret = bpf_map_update_elem(&flowstracker, &flowid, &new_flowm, BPF_NOEXIST);
            if (ret != 0) {
                bpf_printk("error adding new flow %d\n", ret); 
                //maybe because map is full -> send to userspace via ringbuf to avoid losing flow
                new_flowm.syn_or_udp_to_rb = true;
                if (submit_flow_record(flowid, new_flowm) == TC_ACT_OK) {
                    return TC_ACT_OK;
                }   
                //if tcp set syndidntfitsentrb to true
                if (pkt->protocol == IPPROTO_TCP) {
                    syndidntfitsentrb = true; // didnt fit, sent to userspace via ringbuf successfully        
                }    
            }
            //syndidntfitsentrb = false;
        } else{          
            //es un tcp no syn que no existe en el hashmap, 
            //enviar a userspace para revisar alla si pertenece a un flujo que se inicio en el userspace por el ringbuf
            //pero solo si ya se envio alguna vez un syn a userspace
            //ademas senalizarlo
            if (syndidntfitsentrb == true) {
                new_flowm.syn_or_udp_to_rb = false;
                if (submit_flow_record(flowid, new_flowm) == TC_ACT_OK) {
                    return TC_ACT_OK;
                }
            }            
        }
    }
    return TC_ACT_OK;
}

SEC("classifier/ingress")
int connstatsin(struct __sk_buff* skb) {

    if (bpf_skb_pull_data(skb, 0) < 0) {
        //bpf_trace_printk("Ingress: error pulling data\n", sizeof("Ingress: error pulling data\n"));
        return TC_ACT_OK;
    }
    //bpf_trace_printk("Ingress: Pulling data\n", sizeof("Ingress: Pulling data\n"));

    //We only want unicast packets
    if (skb->pkt_type == PACKET_BROADCAST || skb->pkt_type == PACKET_MULTICAST) {
        //bpf_trace_printk("Ingress: Packet is not unicast\n", sizeof("Ingress: Packet is not unicast\n"));
        return TC_ACT_OK;
    }  

    uint8_t* head = (uint8_t*)(long)skb->data;     // Start of the packet data
    uint8_t* tail = (uint8_t*)(long)skb->data_end; // End of the packet data

    if (head + sizeof(struct ethhdr) > tail) { // Not an Ethernet frame
        //bpf_trace_printk("Ingress: Not an Ethernet frame\n",sizeof("Ingress: Not an Ethernet frame\n"));
        return TC_ACT_OK;
    }

    struct packet_t pkt = { 0 };  

    uint32_t offset = 0;

    pkt.len = skb->len;
    pkt.outbound = false;

    if (handle_ip_packet(head, tail, &offset, &pkt) == TC_ACT_OK) {
        //bpf_trace_printk("Ingress: handle_ip_packet returned TC_ACT_OK\n", sizeof("Ingress: handle_ip_packet returned TC_ACT_OK\n"));
        return TC_ACT_OK;
    }

    // Check if TCP/UDP header is fitting this packet
    if (head + offset + sizeof(struct tcphdr) > tail || head + offset + sizeof(struct udphdr) > tail) {
        //bpf_trace_printk("Ingress: TCP/UDP header does not fit in this packet\n", sizeof("Ingress: TCP/UDP header does not fit in this packet\n"));
        return TC_ACT_OK;
    }

    if (handle_ip_segment(head, tail, &offset, &pkt) == TC_ACT_OK) {
        //bpf_trace_printk("Ingress: handle_ip_segment returned TC_ACT_OK\n", sizeof("Ingress: handle_ip_segment returned TC_ACT_OK\n"));
        return TC_ACT_OK;
    }

    if (update_metrics(&pkt) == TC_ACT_OK) {
        //bpf_trace_printk("Ingress: update_metrics returned TC_ACT_OK\n", sizeof("Ingress: update_metrics returned TC_ACT_OK\n"));
        return TC_ACT_OK;
    }

    //bpf_trace_printk("Ingress: Packet processed successfully\n", sizeof("Ingress: Packet processed successfully\n"));
    return TC_ACT_OK;
}

SEC("classifier/egress")
int connstatsout(struct __sk_buff* skb) {

    if (bpf_skb_pull_data(skb, 0) < 0) {
        //bpf_trace_printk("Egress: error pulling data\n", sizeof("Egress: error pulling data\n"));
        return TC_ACT_OK;
    }
    //bpf_trace_printk("Egress: Pulling data\n", sizeof("Egress: Pulling data\n"));

    // We only want unicast packets
    if (skb->pkt_type == PACKET_BROADCAST || skb->pkt_type == PACKET_MULTICAST) {
        //bpf_trace_printk("Egress: Packet is not unicast\n", sizeof("Egress: Packet is not unicast\n"));
        return TC_ACT_OK;
    }  

    uint8_t* head = (uint8_t*)(long)skb->data;     // Start of the packet data
    uint8_t* tail = (uint8_t*)(long)skb->data_end; // End of the packet data

    if (head + sizeof(struct ethhdr) > tail) { // Not an Ethernet frame
        //bpf_trace_printk("Egress: Not an Ethernet frame\n", sizeof("Egress: Not an Ethernet frame\n"));
        return TC_ACT_OK;
    }

    struct packet_t pkt = { 0 };    

    uint32_t offset = 0;

    pkt.len = skb->len;
    pkt.outbound = true;

    if (handle_ip_packet(head, tail, &offset, &pkt) == TC_ACT_OK) {
        //bpf_trace_printk("Egress: handle_ip_packet returned TC_ACT_OK\n", sizeof("Egress: handle_ip_packet returned TC_ACT_OK\n"));
        return TC_ACT_OK;
    }

    // Check if TCP/UDP header is fitting this packet
    if (head + offset + sizeof(struct tcphdr) > tail || head + offset + sizeof(struct udphdr) > tail) {
        //bpf_trace_printk("Egress: TCP/UDP header does not fit in this packet\n", sizeof("Egress: TCP/UDP header does not fit in this packet\n"));
        return TC_ACT_OK;
    }

    if (handle_ip_segment(head, tail, &offset, &pkt) == TC_ACT_OK) {
        //bpf_trace_printk("Egress: handle_ip_segment returned TC_ACT_OK\n", sizeof("Egress: handle_ip_segment returned TC_ACT_OK\n"));
        return TC_ACT_OK;
    }

    if (update_metrics(&pkt) == TC_ACT_OK) {
        //bpf_trace_printk("Egress: update_metrics returned TC_ACT_OK\n", sizeof("Egress: update_metrics returned TC_ACT_OK\n"));
        return TC_ACT_OK;
    }

    //bpf_trace_printk("Egress: Packet processed successfully\n", sizeof("Egress: Packet processed successfully\n"));
    return TC_ACT_OK;
}

char _license[] SEC("license") = "Dual MIT/GPL";
