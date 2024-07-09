package probe

import (
	"context"
	//"sync"

	//"encoding/binary"
	"encoding/csv"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/gabspt/ConnectionStats/clsact"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go probe ../../bpf/connstats_dynamic_packets_tcpreplay_3.c - -O3  -Wall -Werror -Wno-address-of-packed-member

const tenMegaBytes = 1024 * 1024 * 10      // 10MB
const twentyMegaBytes = tenMegaBytes * 2   // 20MB
const fortyMegaBytes = twentyMegaBytes * 2 // 40MB

const TCP_IDLE_TIME = 300000000000 //300000ms = 5min
const UDP_IDLE_TIME = 200000000000 //200000ms = 3min and 20s
const SINGLETON_TIME = 10000000000 //10000ms = 10s

const scaleFactor = 1000

var ipProtoNums = map[uint8]string{
	6:  "TCP",
	17: "UDP",
}

type probe struct {
	iface      netlink.Link
	handle     *netlink.Handle
	qdisc      *clsact.ClsAct
	bpfObjects *probeObjects
	filters    []*netlink.BpfFilter
}

type EvictSubmittion struct {
	evict bool
}

func setRlimit() error {
	//log.Printf("Setting rlimit - soft: %v, hard: %v", twentyMegaBytes, fortyMegaBytes)

	return unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
		Cur: tenMegaBytes,
		Max: fortyMegaBytes,
	})
}

func (p *probe) loadObjects(pktAgrupation int) error {
	//log.Printf("Loading probe object to kernel")

	objs := probeObjects{}

	if err := loadProbeObjects(&objs, nil); err != nil {
		return err
	}

	keyp := uint32(0)
	valuep := uint32(pktAgrupation)
	err := objs.probeMaps.Userconfig.Update(&keyp, &valuep, ebpf.UpdateAny)
	if err != nil {
		return err
	}

	p.bpfObjects = &objs

	return nil
}

func (p *probe) createQdisc() error {
	//log.Printf("Creating qdisc")

	p.qdisc = clsact.NewClsAct(&netlink.QdiscAttrs{
		LinkIndex: p.iface.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	})

	if err := p.handle.QdiscAdd(p.qdisc); err != nil {
		if err := p.handle.QdiscReplace(p.qdisc); err != nil {
			return err
		}
	}

	return nil
}

func (p *probe) createFilters() error {
	//log.Printf("Creating qdisc filters")

	addFilterin := func(attrs netlink.FilterAttrs) {
		p.filters = append(p.filters, &netlink.BpfFilter{
			FilterAttrs:  attrs,
			Fd:           p.bpfObjects.probePrograms.Connstatsin.FD(),
			DirectAction: true,
		})
	}

	addFilterin(netlink.FilterAttrs{
		LinkIndex: p.iface.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_MIN_INGRESS,
		Protocol:  unix.ETH_P_IP,
	})

	addFilterin(netlink.FilterAttrs{
		LinkIndex: p.iface.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_MIN_INGRESS,
		Protocol:  unix.ETH_P_IPV6,
	})

	for _, filter := range p.filters {
		if err := p.handle.FilterAdd(filter); err != nil {
			if err := p.handle.FilterReplace(filter); err != nil {
				return err
			}
		}
	}

	return nil
}

func newProbe(iface netlink.Link, pktAgrupation int) (*probe, error) {
	//log.Println("Creating a new probe")

	if err := setRlimit(); err != nil {
		log.Printf("Failed setting rlimit: %v", err)
		return nil, err
	}

	handle, err := netlink.NewHandle(unix.NETLINK_ROUTE)

	if err != nil {
		log.Printf("Failed getting netlink handle: %v", err)
		return nil, err
	}

	prbe := probe{
		iface:  iface,
		handle: handle,
	}

	if err := prbe.loadObjects(pktAgrupation); err != nil {
		log.Printf("Failed loading probe objects: %v", err)
		return nil, err
	}

	if err := prbe.createQdisc(); err != nil {
		log.Printf("Failed creating qdisc: %v", err)
		return nil, err
	}

	if err := prbe.createFilters(); err != nil {
		log.Printf("Failed creating qdisc filters: %v", err)
		return nil, err
	}

	return &prbe, nil
}

// func print global metrics
func (p *probe) PrintGlobalMetrics() {
	globalmetricsmap := p.bpfObjects.probeMaps.Globalmetrics
	keyg := uint32(0)
	var gm probeGlobalMetrics
	err := globalmetricsmap.Lookup(keyg, &gm)
	if err != nil {
		log.Fatalf("Failed to lookup global metrics: %v", err)
	}

	log.Printf("")
	log.Printf("Global metrics:")
	log.Printf("---------------")
	log.Printf("Total packets processed: %v", gm.TotalProcessedpackets)
	log.Printf("Total packets analyzed (TCP+UDP): %v", gm.TotalTcppackets+gm.TotalUdppackets)
	log.Printf("Total TCP packets analyzed: %v", gm.TotalTcppackets)
	log.Printf("Total UDP packets analyzed: %v", gm.TotalUdppackets)
	//log.Printf("Total flows analyzed: %v", gm.TotalFlows)
	log.Printf("Total TCP flows analyzed: %v", gm.TotalTcpflows)
	log.Printf("Total UDP flows analyzed: %v", gm.TotalUdpflows)
	log.Printf("")
}

func writeFlowStatsToCSV(w *csv.Writer, flowStats probeFlowStats) error {
	//func writeFlowStatsToCSV(w *csv.Writer, flowStats probeFlowMetrics) error {
	// Write the flow stats to the CSV file
	protoc, ok := ipProtoNums[flowStats.FlowTuple.Protocol]
	if !ok {
		log.Print("Failed fetching protocol number: ", flowStats.FlowTuple.Protocol)
	}
	ipAndPortA := fmt.Sprintf("%s:%d", net.IP(flowStats.FlowTuple.A_ip.In6U.U6Addr8[:]).String(), flowStats.FlowTuple.A_port)
	ipAndPortB := fmt.Sprintf("%s:%d", net.IP(flowStats.FlowTuple.B_ip.In6U.U6Addr8[:]).String(), flowStats.FlowTuple.B_port)

	record := []string{
		protoc,
		ipAndPortA,
		ipAndPortB,
		// strconv.Itoa(int(flowStats.PacketsIn)),
		// strconv.Itoa(int(flowStats.PacketsOut)),
		// strconv.Itoa(int(flowStats.BytesIn)),
		// strconv.Itoa(int(flowStats.BytesOut)),
		// strconv.FormatFloat(float64(flowStats.TsCurrent-flowStats.TsStart), 'f', 3, 64),
		strconv.FormatFloat(float64(flowStats.Inpps)/scaleFactor, 'f', 3, 64),
		strconv.FormatFloat(float64(flowStats.Outpps)/scaleFactor, 'f', 3, 64),
		strconv.FormatFloat(float64(flowStats.Inbpp)/scaleFactor, 'f', 3, 64),
		strconv.FormatFloat(float64(flowStats.Outbpp)/scaleFactor, 'f', 3, 64),
		strconv.FormatFloat(float64(flowStats.Inboutb)/scaleFactor, 'f', 3, 64),
		strconv.FormatFloat(float64(flowStats.Inpoutp)/scaleFactor, 'f', 3, 64),
	}

	err := w.Write(record)
	if err != nil {
		return err
	}

	return nil
}

func writeBlankLineToFile(w *csv.Writer) error {
	// Write a blank line to the log file
	err := w.Write([]string{"", "", "", "", "", "", "", ""})
	if err != nil {
		log.Printf("Failed to write to CSV: %v", err)
	}
	return err
}

func GenerateStats(ft *FlowTable, w *csv.Writer) {
	ft.Range(func(key, value interface{}) bool {
		flowStats := value.(probeFlowStats)
		//flowStats := value.(probeFlowMetrics)
		if err := writeFlowStatsToCSV(w, flowStats); err != nil {
			log.Println(err)
		}
		return true
	})
	if err := writeBlankLineToFile(w); err != nil {
		log.Println(err)
	}
	w.Flush()
}

func (p *probe) Close() error {

	p.PrintGlobalMetrics()

	log.Println("Removing qdisc")
	if err := p.handle.QdiscDel(p.qdisc); err != nil {
		log.Println("Failed deleting qdisc")
		return err
	}

	log.Println("Deleting handle")
	p.handle.Delete()

	log.Println("Closing eBPF object")
	if err := p.bpfObjects.Close(); err != nil {
		log.Println("Failed closing eBPF object")
		return err
	}

	return nil
}

func UnmarshalEvictSubmittion(in []byte) (EvictSubmittion, bool) {
	return EvictSubmittion{
		evict: in[0] == 1,
	}, true
}

// func EvictMapEntries(flowsmap *ebpf.Map, w *csv.Writer, mu *sync.Mutex) {
func EvictMapEntries(flowsmap *ebpf.Map, w *csv.Writer) {
	//mu.Lock()
	//defer mu.Unlock()

	var newft = NewFlowTable()
	iterator := flowsmap.Iterate()
	var flowhash uint64
	var flowstats probeFlowStats
	//var flowstats probeFlowMetrics
	for iterator.Next(&flowhash, &flowstats) {
		newft.Store(flowhash, flowstats)
	}
	GenerateStats(newft, w)
}

// Run starts the probe
func Run(ctx context.Context, iface netlink.Link, pktAgrupation int) error {
	//log.Printf("Starting up the probe at interface %v", iface.Attrs().Name)

	probe, err := newProbe(iface, pktAgrupation)
	if err != nil {
		return err
	}

	flowsmap := probe.bpfObjects.probeMaps.Flowstats
	//flowsmap := probe.bpfObjects.probeMaps.Flowstracker

	// Create a ring buffer reader
	pipe := probe.bpfObjects.probeMaps.Pipe
	ringreader, err := ringbuf.NewReader(pipe)
	if err != nil {
		log.Println("Failed creating ringbuf reader")
		return err
	}

	//Open the log file and create a new csv writer writing to the opened file
	filename := "flows_stats1000_2.csv"
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Println(err)
	}
	defer f.Close()

	w := csv.NewWriter(f)

	//var mu sync.Mutex

	go func() {
		for {
			event, err := ringreader.Read()
			if err != nil {
				log.Printf("Failed reading ringbuf event: %v", err)
				return
			}

			//unmarshal evict submittion
			evictsubmittion, ok := UnmarshalEvictSubmittion(event.RawSample)
			if !ok {
				log.Printf("Could not unmarshall evict submittion: %+v", event.RawSample)
				continue
			}

			// if evict submittion is true, erase flows to delete from ft, evict the flowhashes from the flowstracker map and generate stats
			if evictsubmittion.evict {
				log.Printf("Eviction")
				//go EvictMapEntries(flowsmap, w, &mu)
				EvictMapEntries(flowsmap, w)
				//log.Printf("Eviction at %v packets, ft size %v", evictsubmittion.packet_counter, ft.Size()) //counts the number of evictions
				//EvictMapEntries(flowstrackermap, w)
				//GenerateStats(ft)
			}
		}
	}()

	// Wait for the context to be done
	for {
		<-ctx.Done()
		return probe.Close()
	}
}
