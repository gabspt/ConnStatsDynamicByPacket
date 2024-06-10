package probe

import (
	"log"
	//"net/netip"
	"sync"
	//"time"
)

// type FlowTable struct {
// 	Ticker *time.Ticker
// 	sync.Map
// }

type FlowTable struct {
	sync.Map
}

// type Connection struct {
// 	Protocol    string
// 	L_ip        netip.Addr
// 	R_ip        netip.Addr
// 	L_Port      uint16
// 	R_Port      uint16
// 	Packets_in  uint32
// 	Packets_out uint32
// 	Ts_start    uint64
// 	Ts_current  uint64
// 	Bytes_in    uint64
// 	Bytes_out   uint64
// }

// NewFlowTable Constructs a new FlowTable
//
//	func NewFlowTable() *FlowTable {
//		return &FlowTable{Ticker: time.NewTicker(time.Second * 10)}
//	}
func NewFlowTable() *FlowTable {
	return &FlowTable{}
}

// delete deletes connection hash and its data from the FlowTable
func (table *FlowTable) Remove(key any) {
	_, found := table.Load(key)

	if found {
		// log.Printf("Removing hash %v from flow table", hash)
		table.Delete(key)
	} //else {
	//log.Printf("hash %v is not in flow table", key)
	//}
}

func (table *FlowTable) CountActiveConns() {
	counter := 0
	table.Range(func(hash, value interface{}) bool {
		counter++
		return true
	})
	log.Printf("There are %v active connections", counter)
}

// var ipProtoNums = map[uint8]string{
// 	6:  "TCP",
// 	17: "UDP",
// }

// type IPStruct struct {
// 	In6U struct {
// 		U6Addr8 [16]uint8
// 	}
// }

// func convertToNetIPAddr(ipStruct IPStruct) (netip.Addr, bool) {
// 	b := make([]byte, 16)
// 	for i, v := range ipStruct.In6U.U6Addr8 {
// 		b[i] = byte(v)
// 	}
// 	addr, ok := netip.AddrFromSlice(b)
// 	return addr, ok
// }

// func (table *FlowTable) GetConnList() []Connection {
// 	var connlist []Connection
// 	table.Range(func(key, value interface{}) bool {

// 		_, okid := key.(uint64)
// 		fm, okm := value.(probeFlowMetrics)

// 		if okid && okm {

// 			protoc, ok := ipProtoNums[fm.FlowTuple.Protocol]
// 			if !ok {
// 				log.Print("Failed fetching protocol number: ", fm.FlowTuple.Protocol)
// 			}
// 			aip, ok := convertToNetIPAddr(fm.FlowTuple.A_ip)
// 			if !ok {
// 				log.Print("Failed converting IP address: ", fm.FlowTuple.A_ip)
// 			}
// 			bip, ok := convertToNetIPAddr(fm.FlowTuple.B_ip)
// 			if !ok {
// 				log.Print("Failed converting IP address: ", fm.FlowTuple.B_ip)
// 			}

// 			connection := Connection{
// 				Protocol:    protoc,
// 				L_ip:        aip,
// 				R_ip:        bip,
// 				L_Port:      fm.FlowTuple.A_port,
// 				R_Port:      fm.FlowTuple.B_port,
// 				Packets_in:  fm.PacketsIn,
// 				Packets_out: fm.PacketsOut,
// 				Ts_start:    fm.TsStart,
// 				Ts_current:  fm.TsCurrent,
// 				Bytes_in:    fm.BytesIn,
// 				Bytes_out:   fm.BytesOut,
// 			}

// 			connlist = append(connlist, connection)
// 		}
// 		return true
// 	})
// 	return connlist
// }

// UpdateFlowTable updates the FlowTable and returns a boolean indicating if the flow was updated or not
// func (table *FlowTable) UpdateFlowTable(flowhash uint64, fm probeFlowMetrics) bool {
// func (table *FlowTable) UpdateFlowTable(flowhash uint64, fm probeFlowMetrics) {

// 	value, found := table.Load(flowhash)
// 	if !found { // Flow does not exist in the flow table add tal cual
// 		table.Store(flowhash, fm)
// 	} else {
// 		existingflowm, ok := value.(probeFlowMetrics)
// 		if ok {
// 			if existingflowm.TsCurrent != fm.TsCurrent { //solo se actualiza el flujo si el timestamp current no es el mismo
// 				fm.PacketsIn += existingflowm.PacketsIn
// 				fm.PacketsOut += existingflowm.PacketsOut
// 				fm.BytesIn += existingflowm.BytesIn
// 				fm.BytesOut += existingflowm.BytesOut
// 				if existingflowm.TsStart < fm.TsStart {
// 					fm.TsStart = existingflowm.TsStart
// 				}
// 				if existingflowm.TsCurrent > fm.TsCurrent {
// 					fm.TsCurrent = existingflowm.TsCurrent
// 				}
// 				table.Store(flowhash, fm)
// 			}
// 		} else {
// 			log.Printf("Could not convert existing value to probeFlowMetrics UpdateFlowTable: %+v", value)
// 			//ft.Store(fid, flowmetrics) //decidir si en este caso se queda la tabla como estaba o se le pone lo del flowstracker, ahora mismo se queda como estaba, maybe ca,biar dependiendo de experimentos
// 		}
// 	}
// }

// func (table *FlowTable) UpdateFlowTable(flowhash uint64, fm probeFlowMetrics) {

// 	value, found := table.Load(flowhash)
// 	if !found { // Flow does not exist in the flow table add tal cual
// 		table.Store(flowhash, fm)
// 	} else {
// 		if fm.FlowTuple.Protocol == 6 { //tcp //es el mismo flujo udp que inicie en el hash map
// 			table.Store(flowhash, fm)
// 		} else {
// 			existingflowm, ok := value.(probeFlowMetrics)
// 			if ok {
// 				if existingflowm.TsStart == fm.TsStart { //es el mismo flujo udp que inicie en el hash map (solo upd porque los tcp q se envian luego de iniciados en ringbuf no se agregan en el hash map)
// 					table.Store(flowhash, fm)
// 				} else {
// 					log.Println("nothing")
// 				}
// 			}
// 		}

// 		existingflowm, ok := value.(probeFlowMetrics)
// 		if ok {
// 			if existingflowm.TsStart == fm.TsStart { //es el mismo flujo que inicie en el hash map

// 			}
// 			// if existingflowm.TsCurrent != fm.TsCurrent { //solo se actualiza el flujo si el timestamp current no es el mismo
// 			// 	fm.PacketsIn += existingflowm.PacketsIn
// 			// 	fm.PacketsOut += existingflowm.PacketsOut
// 			// 	fm.BytesIn += existingflowm.BytesIn
// 			// 	fm.BytesOut += existingflowm.BytesOut
// 			// 	if existingflowm.TsStart < fm.TsStart {
// 			// 		fm.TsStart = existingflowm.TsStart
// 			// 	}
// 			// 	if existingflowm.TsCurrent > fm.TsCurrent {
// 			// 		fm.TsCurrent = existingflowm.TsCurrent
// 			// 	}
// 			// 	table.Store(flowhash, fm)
// 			// }
// 		} else {
// 			log.Printf("Could not convert existing value to probeFlowMetrics UpdateFlowTable: %+v", value)
// 			//ft.Store(fid, flowmetrics) //decidir si en este caso se queda la tabla como estaba o se le pone lo del flowstracker, ahora mismo se queda como estaba, maybe ca,biar dependiendo de experimentos
// 		}
// 	}
// }

func (table *FlowTable) UpdateFlowTableIfSynOrUdpToRb(flowhash uint64, fm probeFlowMetrics) {

	value, found := table.Load(flowhash)
	if !found { // Flow does not exist in the flow table add tal cual
		table.Store(flowhash, fm)
	} else {
		existingflowm, ok := value.(probeFlowMetrics)
		//existingflowm, ok := value.(probeFlowMetrics)
		if ok {
			if existingflowm.TsStart < fm.TsStart { // es lo logico
				if existingflowm.FlowTuple != fm.FlowTuple {
					//son estadisticas del flujo en sentido contrario
					fm.PacketsIn += existingflowm.PacketsOut
					fm.PacketsOut += existingflowm.PacketsIn
					fm.BytesIn += existingflowm.BytesOut
					fm.BytesOut += existingflowm.BytesIn
					fm.FlowTuple = existingflowm.FlowTuple
				} else {
					fm.PacketsIn += existingflowm.PacketsIn
					fm.PacketsOut += existingflowm.PacketsOut
					fm.BytesIn += existingflowm.BytesIn
					fm.BytesOut += existingflowm.BytesOut
				}
				fm.TsStart = existingflowm.TsStart
				if existingflowm.TsCurrent > fm.TsCurrent {
					fm.TsCurrent = existingflowm.TsCurrent
				}
				table.Store(flowhash, fm)
			}
		} else {
			log.Printf("Could not convert existing value to probeFlowMetrics UpdateFlowTableIfSynOrUdpToRb: %+v", value)
			//ft.Store(fid, flowmetrics) //decidir si en este caso se queda la tabla como estaba o se le pone lo del flowstracker, ahora mismo se queda como estaba, maybe ca,biar dependiendo de experimentos
		}
	}
}

// UpdateFlowTableIfExists updates the FlowTable if the flow exists
func (table *FlowTable) UpdateFlowTableIfExists(flowhash uint64, fm probeFlowMetrics) {
	//lo agrego solo si existe en el flowtable, si no existe no lo agrego porque no es un flujo nuevo
	value, found := table.Load(flowhash)
	if found {
		existingflowm, ok := value.(probeFlowMetrics)
		if ok {
			if existingflowm.TsStart < fm.TsStart { // es lo logico
				if existingflowm.FlowTuple != fm.FlowTuple {
					//son estadisticas del flujo en sentido contrario
					fm.PacketsIn += existingflowm.PacketsOut
					fm.PacketsOut += existingflowm.PacketsIn
					fm.BytesIn += existingflowm.BytesOut
					fm.BytesOut += existingflowm.BytesIn
					fm.FlowTuple = existingflowm.FlowTuple
				} else {
					fm.PacketsIn += existingflowm.PacketsIn
					fm.PacketsOut += existingflowm.PacketsOut
					fm.BytesIn += existingflowm.BytesIn
					fm.BytesOut += existingflowm.BytesOut
				}
				fm.TsStart = existingflowm.TsStart
				if existingflowm.TsCurrent > fm.TsCurrent {
					fm.TsCurrent = existingflowm.TsCurrent
				}
				table.Store(flowhash, fm)
				//log.Printf("Stored flow key: %+v,  metrics: %+v", fid, fm)
			}
		} else {
			log.Printf("Could not convert existing value to probeFlowMetrics UpdateFlowTableIfExists: %+v", value)
		}
	}
}

// Size returns the size of the FlowTable
func (ft *FlowTable) Size() int {
	count := 0
	ft.Range(func(key, value interface{}) bool {
		count++
		return true
	})
	return count
}

// PrintFlowTable prints the FlowTable
func (ft *FlowTable) PrintFlowTable() {
	ft.Range(func(key, value interface{}) bool {
		log.Printf("Key: %v, Value: %v\n", key, value)
		return true
	})
	log.Printf("FlowTable size: %v\n", ft.Size())
	log.Printf("")
}
