package scan

import (
	"encoding/hex"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"net"
)

func getTcpPacketBuf(sourceIp, remoteIp string, srcPort, dstPort int, dstMac net.HardwareAddr) gopacket.SerializeBuffer {
	srcMAC, _ := hex.DecodeString("b2968175b211")
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr(srcMAC),
		DstMAC:       dstMac,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Id:       0,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.ParseIP(sourceIp).To4(),
		//DstIP:    net.ParseIP("194.61.120.104").To4(),
		DstIP: net.ParseIP(remoteIp).To4(),
	}
	tcpOption := layers.TCPOption{
		OptionType:   layers.TCPOptionKindMSS,
		OptionLength: 4,
		OptionData:   []byte{0x05, 0xB4},
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		Window: 1024,
		Seq:     1234,
		SYN:     true,
		Options: []layers.TCPOption{tcpOption},
	}
	tcp.SetNetworkLayerForChecksum(ip)
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp)
	if err != nil {
		panic(err)
	}
	return buf
}
