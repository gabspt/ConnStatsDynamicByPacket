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
#include <linux/types.h>
#include <stddef.h>
#include <string.h>

//FastHash
static __u64 fasthash_mix(__u64 h) {
	h ^= h >> 23;
	h *= 0x2127599bf4325c37ULL;
	h ^= h >> 47;
	return h;
}

__u64 fasthash64(const void *buf, __u64 len, __u64 seed)
{
	const __u64 m = 0x880355f21e6d1965ULL;
	const __u64 *pos = (const __u64 *)buf;
	const __u64 *end = pos + (len / 8);
	const unsigned char *pos2;
	__u64 h = seed ^ (len * m);
	__u64 v;

	while (pos != end) {
		v  = *pos++;
		h ^= fasthash_mix(v);
		h *= m;
	}

	pos2 = (const unsigned char*)pos;
	v = 0;

	switch (len & 7) {
	case 7: v ^= (__u64)pos2[6] << 48;
	case 6: v ^= (__u64)pos2[5] << 40;
	case 5: v ^= (__u64)pos2[4] << 32;
	case 4: v ^= (__u64)pos2[3] << 24;
	case 3: v ^= (__u64)pos2[2] << 16;
	case 2: v ^= (__u64)pos2[1] << 8;
	case 1: v ^= (__u64)pos2[0];
		h ^= fasthash_mix(v);
		h *= m;
	}

	return fasthash_mix(h);
}

// Flow metering

#define SCALE_FACTOR 1000
#define NANOS_PER_SECOND 1000000000

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
    __u32 len;
};
struct flow_tuple {
    struct in6_addr a_ip;
    struct in6_addr b_ip;
    __be16 a_port;
    __be16 b_port;
    __u8 protocol;
};
struct flow_metrics {
    struct flow_tuple flow_tuple;  
    __u32 packets_in;
    __u32 packets_out;
    __u64 bytes_in;
    __u64 bytes_out;
    __u64 ts_start;
    __u64 ts_current;
    __u8 fin_counter;
    __u8 ack_counter;
    //__u8 flow_closed; // 0 flow open, 1 flow ended normally, 2 flow ended anormally
};

struct flow_stats {
    struct flow_tuple flow_tuple; 
    //__u32 packets_in;
    //__u32 packets_out;
    //__u64 bytes_in;
    //__u64 bytes_out;
    //__u64 ts_start;
    //__u64 ts_current; 
    __u64 inpps; //inbound packets per second
    __u64 outpps; //outbound packets per second
    __u64 inbpp; //inbound bytes per packet
    __u64 outbpp; //outbound bytes per packet
    __u64 inboutb; //ratio inbound/outbound bytes
    __u64 inpoutp; //ratio inbound/outbound packets
};

struct evict_submittion {
    bool evict;
};

struct global_metrics {
    __u64 total_processedpackets; 
    __u64 total_tcppackets;
    __u64 total_udppackets;
    __u64 total_tcpflows;
    __u64 total_udpflows;
};

__u32 pkt_aggregation_value = 0;
bool initialized = false;
__u64 tcpudppackets = 0;

// Maps
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);    
} pipe SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1 << 24);
    __type(key, __u64);
    __type(value, struct flow_metrics);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} flowstracker SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1 << 24);
    __type(key, __u64);
    __type(value, struct flow_stats);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} flowstats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1 );
    __type(key, __u32);
    __type(value, struct global_metrics); 
} globalmetrics SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1 );
    __type(key, __u32);
    __type(value, __u32); 
} userconfig SEC(".maps");

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

static inline int ipv6_addr_cmp(struct in6_addr *a, struct in6_addr *b) {
    for (int i = 0; i < 4; i++) {
        if (a->s6_addr32[i] < b->s6_addr32[i])
            return -1;
        else if (a->s6_addr32[i] > b->s6_addr32[i])
            return 1;
    }
    return 0;
}

static inline void normalize_flow_id(struct flow_tuple *flow) {
    if (ipv6_addr_cmp(&flow->a_ip, &flow->b_ip) > 0 ||
        (ipv6_addr_cmp(&flow->a_ip, &flow->b_ip) == 0 && flow->a_port > flow->b_port)) {
        struct in6_addr temp_ip = flow->a_ip;
        flow->a_ip = flow->b_ip;
        flow->b_ip = temp_ip;

        __be16 temp_port = flow->a_port;
        flow->a_port = flow->b_port;
        flow->b_port = temp_port;
    }
}

static inline __u64 calculate_flow_id_hash(struct flow_tuple *flow) {
    struct flow_tuple normalized_flow = *flow;
    normalize_flow_id(&normalized_flow);
    return fasthash64(&normalized_flow, sizeof(struct flow_tuple), 123456789); // use a seed of your choice
}

static inline bool are_equal(struct in6_addr a, struct in6_addr b) {
    return ((a.s6_addr32[0] == b.s6_addr32[0]) &&
            (a.s6_addr32[1] == b.s6_addr32[1]) &&
            (a.s6_addr32[2] == b.s6_addr32[2]) &&
            (a.s6_addr32[3] == b.s6_addr32[3]));
}

//submit evict submittion to userspace method
static inline int submit_evict_submittion(struct evict_submittion *evictsubmittion) {
    struct evict_submittion *evictsubmittionrecord = (struct evict_submittion *)bpf_ringbuf_reserve(&pipe, sizeof(struct evict_submittion), 0);
    if (!evictsubmittionrecord) {
        return TC_ACT_OK;
    }
    evictsubmittionrecord->evict = evictsubmittion->evict;
    bpf_ringbuf_submit(evictsubmittionrecord, 0);
    return 0;
}


static inline void calculate_stats(struct flow_metrics *flowmetrics, struct flow_stats *flowstats) {
    flowstats->flow_tuple = flowmetrics->flow_tuple;

    __u64 duration = (flowmetrics->ts_current - flowmetrics->ts_start);

    if (duration > 0) {
        flowstats->inpps = ((__u64)flowmetrics->packets_in * SCALE_FACTOR * NANOS_PER_SECOND) / duration;
        flowstats->outpps = ((__u64)flowmetrics->packets_out * SCALE_FACTOR * NANOS_PER_SECOND) / duration;
    } else {
        flowstats->inpps = 0;
        flowstats->outpps = 0;
    }

    if (flowmetrics->packets_in > 0) {
        flowstats->inbpp = (flowmetrics->bytes_in * SCALE_FACTOR) / flowmetrics->packets_in;
    } else {
        flowstats->inbpp = 0;
    }

    if (flowmetrics->packets_out > 0) {
        flowstats->outbpp = (flowmetrics->bytes_out * SCALE_FACTOR) / flowmetrics->packets_out;
    } else {
        flowstats->outbpp = 0;
    }

    if (flowmetrics->bytes_out > 0) {
        flowstats->inboutb = (flowmetrics->bytes_in * SCALE_FACTOR) / flowmetrics->bytes_out;
    } else {
        flowstats->inboutb = 0;
    }

    if (flowmetrics->packets_out > 0) {
        flowstats->inpoutp = ((__u64)flowmetrics->packets_in * SCALE_FACTOR) / flowmetrics->packets_out;
    } else {
        flowstats->inpoutp = 0;
    }
}

static inline int update_metrics(struct packet_t *pkt, struct global_metrics *globalm) {
    //initialze packet aggregation level value
    if (!initialized) {
        __u32 keyp = 0;
        __u32 *pkt_aggregation = bpf_map_lookup_elem(&userconfig, &keyp);
        if (pkt_aggregation != NULL) {
            pkt_aggregation_value = *pkt_aggregation;
        }
        initialized = true;
    }

    //update global metrics total_packets, total_tcp_packets, total_udp_packets 
    tcpudppackets += 1;
    if (pkt->protocol == IPPROTO_TCP) {
        globalm->total_tcppackets += 1;
    } else {
        globalm->total_udppackets += 1;
    }

    //conformando el flow id
    struct flow_tuple flowtuple = {0};
    flowtuple.a_ip = pkt->src_ip;
    flowtuple.b_ip = pkt->dst_ip;
    flowtuple.a_port = bpf_ntohs(pkt->src_port);
    flowtuple.b_port = bpf_ntohs(pkt->dst_port);
    flowtuple.protocol = pkt->protocol;
   
    __u64 flowhash = calculate_flow_id_hash(&flowtuple);

    struct flow_metrics *flowmetrics = bpf_map_lookup_elem(&flowstracker, &flowhash);
    if (flowmetrics != NULL) {
        //flow exists -> update metrics
        flowmetrics->ts_current = pkt->ts;
        if (are_equal(pkt->src_ip, flowmetrics->flow_tuple.a_ip)) { 
            flowmetrics->packets_out += 1;
            flowmetrics->bytes_out += pkt->len;
        } else { //update ingress metrics
            flowmetrics->packets_in += 1;
            flowmetrics->bytes_in += pkt->len;
        }
        if (pkt->fin == true && pkt->ack == true) { // FIN/ACK segment observed
            flowmetrics->fin_counter += 1;
        }
        if (flowmetrics->fin_counter>=1 && pkt->ack == true && pkt->fin == false && pkt->syn == false && pkt->rst == false) { //flow ended normally  
            flowmetrics->ack_counter += 1;
        }

        //after 2 fin packets and 2 ack are received consider flow ended normally, or if rst packet recieved consider flow ended anormally, -> delete flow from map
        if (flowmetrics->fin_counter>=2 && flowmetrics->ack_counter>=2 && pkt->ack == true && pkt->fin == false && pkt->syn == false && pkt->rst == false) { //flow ended normally  
            //flowmetrics->flow_closed = 1;
            bpf_map_delete_elem(&flowstracker, &flowhash);
            bpf_map_delete_elem(&flowstats, &flowhash);
        } else if (pkt->rst == true) { //flow ended anormally
            //flowmetrics->flow_closed = 2;
            bpf_map_delete_elem(&flowstracker, &flowhash);
            bpf_map_delete_elem(&flowstats, &flowhash);
        } else { //flow still open -> update hash map and return
            //update flow metrics map
            long ret1 = bpf_map_update_elem(&flowstracker, &flowhash, flowmetrics, BPF_EXIST);
            if (ret1 != 0) {
                return TC_ACT_OK;
            }

            //calculate flow stats to update flow stats map
            struct flow_stats flow_stats = {0};
            //flow_stats.packets_in = flowmetrics->packets_in;
            //flow_stats.packets_out = flowmetrics->packets_out;
            //flow_stats.bytes_in = flowmetrics->bytes_in;
            //flow_stats.bytes_out = flowmetrics->bytes_out;
            //flow_stats.ts_start = flowmetrics->ts_start;
            //flow_stats.ts_current = flowmetrics->ts_current;
            calculate_stats(flowmetrics, &flow_stats);
            long ret2 = bpf_map_update_elem(&flowstats, &flowhash, &flow_stats, BPF_EXIST);
            if (ret2 != 0) {
                return TC_ACT_OK;
            }         
        }

    } else {
        //flow doesn't exist
        
        if ((pkt->syn == true && pkt->ack == false) || (pkt->protocol == IPPROTO_UDP)) { //new tcp syn or udp connection, add to flowstracker map
            //create new flow TCP or UDP

            //update total flows global metrics
            if (pkt->protocol == IPPROTO_TCP) {
                globalm->total_tcpflows += 1;
            } else {
                globalm->total_udpflows += 1;
            }

            struct flow_metrics new_flowm = {0};
            new_flowm.flow_tuple = flowtuple;
            new_flowm.ts_start = pkt->ts;    
            new_flowm.ts_current = pkt->ts;
            new_flowm.packets_out = 1;
            new_flowm.bytes_out = pkt->len;

            //add flow to flowstracker hash map
            long ret1 = bpf_map_update_elem(&flowstracker, &flowhash, &new_flowm, BPF_NOEXIST);
            if (ret1 != 0) {
                return TC_ACT_OK;  
            }
            // calculate flow stats to update flow stats map
            struct flow_stats flow_stats = {0};
            //flow_stats.packets_in = new_flowm.packets_in;
            //flow_stats.packets_out = new_flowm.packets_out;
            //flow_stats.bytes_in = new_flowm.bytes_in;
            //flow_stats.bytes_out = new_flowm.bytes_out;
            //flow_stats.ts_start = new_flowm.ts_start;
            //flow_stats.ts_current = new_flowm.ts_current;
            calculate_stats(&new_flowm, &flow_stats);
            long ret2 = bpf_map_update_elem(&flowstats, &flowhash, &flow_stats, BPF_NOEXIST);
            if (ret2 != 0) {
                return TC_ACT_OK;
            }  
        } 
    }
    
    //Comprobar si ya hay que generar estadisticas
    if (tcpudppackets >= pkt_aggregation_value){
        tcpudppackets = 0;
        struct evict_submittion evictsubmittion = {0};
        evictsubmittion.evict = true;
        //evictsubmittion.packet_counter = tcpudppackets;
        //send evict submittion to userspace
        if (submit_evict_submittion(&evictsubmittion) == TC_ACT_OK) {
            return TC_ACT_OK;
        }
    }

    //__u32 keygb = 0;
    //bpf_map_update_elem(&globalmetrics, &keygb, globalm, BPF_ANY);

    return TC_ACT_OK;
}

SEC("classifier/ingress")
int connstatsin(struct __sk_buff* skb) {

    if (bpf_skb_pull_data(skb, 0) < 0) {
        return TC_ACT_OK;
    }

    //update global metrics total_packets, total_tcp_packets, total_udp_packets 
    __u32 keygb = 0;
    struct global_metrics *globalm = bpf_map_lookup_elem(&globalmetrics, &keygb);
    if (!globalm) {
        struct global_metrics new_globalm = {0};
        //new_globalm.total_processedpackets = 1;
        bpf_map_update_elem(&globalmetrics, &keygb, &new_globalm, BPF_ANY);
        globalm = &new_globalm;
    } //else {
    //     globalm->total_processedpackets += 1;
    //     bpf_map_update_elem(&globalmetrics, &keygb, globalm, BPF_ANY); 
    // }

    globalm->total_processedpackets += 1;

    uint8_t* head = (uint8_t*)(long)skb->data;     // Start of the packet data
    uint8_t* tail = (uint8_t*)(long)skb->data_end; // End of the packet data

    if (head + sizeof(struct ethhdr) > tail) { // Not an Ethernet frame
        return TC_ACT_OK;
    }

    struct packet_t pkt = { 0 };  

    uint32_t offset = 0;

    pkt.len = skb->len;

    if (handle_ip_packet(head, tail, &offset, &pkt) == TC_ACT_OK) {
        goto update_and_return;
        //return TC_ACT_OK;
    }

    // Check if TCP/UDP header is fitting this packet
    if (head + offset + sizeof(struct tcphdr) > tail || head + offset + sizeof(struct udphdr) > tail) {
        goto update_and_return;
        //return TC_ACT_OK;
    }

    if (handle_ip_segment(head, tail, &offset, &pkt) == TC_ACT_OK) {
        goto update_and_return;
        //return TC_ACT_OK;
    }

    if (update_metrics(&pkt, globalm) == TC_ACT_OK) {
        goto update_and_return;
        //return TC_ACT_OK;
    }


    update_and_return:
    // Asegurarse de que global_metrics se actualice antes de salir
        bpf_map_update_elem(&globalmetrics, &keygb, globalm, BPF_ANY);
        return TC_ACT_OK;
}

char _license[] SEC("license") = "Dual MIT/GPL";
