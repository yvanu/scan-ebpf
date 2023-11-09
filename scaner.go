package scan

import (
	"fmt"
	"github.com/asavie/xdp"
	"github.com/asavie/xdp/examples/scan/ebpf"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/vishvananda/netlink"
	"net"
	"time"
)

type Scanner struct {
	nic     string
	queueId int

	dstMac net.HardwareAddr

	link netlink.Link

	program *xdp.Program
	xsk     *xdp.Socket
}

func NewScanner(nic string, queueId int) *Scanner {
	s := &Scanner{
		nic:     nic,
		queueId: queueId,
		dstMac:  getGatewayMac(),
	}
	s.init()
	return s
}

func (s *Scanner) init() {
	link, err := netlink.LinkByName(s.nic)
	if err != nil {
		panic(err)
	}
	s.link = link

	xsk, err := xdp.NewSocket(s.link.Attrs().Index, s.queueId, nil)
	if err != nil {
		panic(err)
	}
	s.xsk = xsk

}

func (s *Scanner) initProgram(port int) {
	program, err := ebpf.NewPortFilter(uint32(port))
	if err != nil {
		panic(err)
	}
	s.program = program
}

func (s *Scanner) closeProgram() {
	s.program.Close()
}

func (s *Scanner) attachProgram() {
	err := s.program.Attach(s.link.Attrs().Index)
	if err != nil {
		panic(err)
	}
}

func (s *Scanner) detachProgram() {
	s.program.Detach(s.link.Attrs().Index)
}

func (s *Scanner) registerProgram() {
	err := s.program.Register(s.queueId, s.xsk.FD())
	if err != nil {
		panic(err)
	}
}

func (s *Scanner) unRegisterProgram() {
	s.program.Unregister(s.queueId)
}

func (s *Scanner) Send(sourceIp, remoteIp string, srcPort, dstPort int) {
	bufList := make([]gopacket.SerializeBuffer, 0)
	for i := 140; i < 150; i++ {
		for j := 1; j < 255; j++ {
			bufList = append(bufList, getTcpPacketBuf(sourceIp, fmt.Sprintf(remoteIp, i, j), srcPort, dstPort, s.dstMac))
		}
	}
	//bufList = append(bufList, getTcpPacketBuf(sourceIp, "43.159.149.32", srcPort, dstPort, s.dstMac))

	//buf := getTcpPacketBuf(sourceIp, remoteIp, srcPort, dstPort, s.dstMac)
	//frameLen := len(buf.Bytes())
	//descs := s.xsk.GetDescs(math.MaxInt32, false)
	//fmt.Println(len(descs))
	//for i := range descs {
	//	copy(s.xsk.GetFrame(descs[i]), bufList[i].Bytes())
	//}
	//copy(s.xsk.GetFrame(desc[0]), buf.Bytes())
	//fmt.Printf("从%s发送syn包到%s\n", sourceIp, remoteIp)

	go func() {
		var err error
		var prev xdp.Stats
		var cur xdp.Stats
		var numPkts uint64
		for i := uint64(0); ; i++ {
			time.Sleep(time.Duration(1) * time.Second)
			cur, err = s.xsk.Stats()
			if err != nil {
				panic(err)
			}
			numPkts = cur.Completed - prev.Completed
			if numPkts == 0 {
				continue
			}
			fmt.Printf("%d packets/s\n", numPkts)
			prev = cur
		}
	}()

	var availableBuf []gopacket.SerializeBuffer
	for {
		if len(bufList) == 0 {
			break
		}
		descs := s.xsk.GetDescs(s.xsk.NumFreeTxSlots(), false)
		if len(descs) > len(bufList) {
			availableBuf = bufList
		} else {
			availableBuf = bufList[:len(descs)]
			bufList = bufList[len(descs):]
		}

		for i := 0; i < len(availableBuf); i++ {
			copy(s.xsk.GetFrame(descs[i]), availableBuf[i].Bytes())
			descs[i].Len = uint32(len(availableBuf[i].Bytes()))
		}

		s.xsk.Transmit(descs)
		//s.xsk.Fill(descs)
		//if n := s.xsk.NumFreeFillSlots(); n > 0 {
		//	s.xsk.Fill(s.xsk.GetDescs(n, false))
		//}
		_, _, err := s.xsk.Poll(-1)
		if err != nil {
			panic(err)
		}
	}

}

func (s *Scanner) Receive(sip string, srcPort int) {
	s.initProgram(srcPort)
	defer s.closeProgram()
	s.attachProgram()
	defer s.detachProgram()
	s.registerProgram()
	defer s.unRegisterProgram()

	count := 0
	var sourceIpMap = make(map[string]bool)
	for {
		if n := s.xsk.NumFreeFillSlots(); n > 0 {
			s.xsk.Fill(s.xsk.GetDescs(n, true))
		}

		//log.Printf("waiting for frame(s) to be received...")
		numRx, _, err := s.xsk.Poll(-1)

		if err != nil {
			fmt.Printf("error: %v\n", err)
			return
		}
		//
		if numRx > 0 {

			rxDescs := s.xsk.Receive(numRx)

			for i := 0; i < len(rxDescs); i++ {
				pktData := s.xsk.GetFrame(rxDescs[i])
				pkt := gopacket.NewPacket(pktData, layers.LayerTypeEthernet, gopacket.Default)
				//log.Printf("received frame:\n%s%+v", hex.Dump(pktData[:]), pkt)
				//fmt.Println("源ip: ", pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4).SrcIP)
				//_ = pkt
				// 过滤掉rst包
				//fmt.Println("源ip: ", pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4).SrcIP)
				//fmt.Println(pkt)
				//count++
				//print(count)
				sourceIp := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4).SrcIP.String()
				if sourceIp != sip {
					tcpPkt := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
					if !tcpPkt.RST {
						if _, exist := sourceIpMap[sourceIp]; !exist {
							count++
							println(count)
							sourceIpMap[sourceIp] = true
							fmt.Println("源ip: ", pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4).SrcIP)
						} else {

						}

					}

					//log.Printf("received frame:\n%s%+v", hex.Dump(pktData[:]), pkt)
					//tcpPkt := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
					//if !tcpPkt.RST {
					//	//log.Printf("received frame:\n%s%+v", hex.Dump(pktData[:]), pkt)
					//	count++
					//}
				}
			}
			//s.xsk.Fill(rxDescs)
		}

	}

}
