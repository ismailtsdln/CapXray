package pcap

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/ismailtasdelen/CapXray/pkg/models"
)

// Parser handles packet decoding
type Parser struct{}

// NewParser creates a new packet parser
func NewParser() *Parser {
	return &Parser{}
}

// Parse converts a gopacket.Packet to a internal Packet model
func (p *Parser) Parse(packet gopacket.Packet) (*models.Packet, error) {
	parsed := &models.Packet{
		Timestamp: packet.Metadata().Timestamp,
		Length:    packet.Metadata().Length,
	}

	// Ethernet layer
	if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
		_ = ethLayer.(*layers.Ethernet)
	}

	// IPv4 layer
	if ip4Layer := packet.Layer(layers.LayerTypeIPv4); ip4Layer != nil {
		ip4 := ip4Layer.(*layers.IPv4)
		parsed.SourceAddress = ip4.SrcIP.String()
		parsed.TargetAddress = ip4.DstIP.String()
		parsed.Protocol = ip4.Protocol.String()
	} else if ip6Layer := packet.Layer(layers.LayerTypeIPv6); ip6Layer != nil {
		ip6 := ip6Layer.(*layers.IPv6)
		parsed.SourceAddress = ip6.SrcIP.String()
		parsed.TargetAddress = ip6.DstIP.String()
		parsed.Protocol = ip6.NextHeader.String()
	} else {
		return nil, fmt.Errorf("no IP layer found")
	}

	// Transport layer
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		parsed.SourcePort = tcp.SrcPort.String()
		parsed.TargetPort = tcp.DstPort.String()
		parsed.TransportLayer = "TCP"
		parsed.Payload = tcp.Payload
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		parsed.SourcePort = udp.SrcPort.String()
		parsed.TargetPort = udp.DstPort.String()
		parsed.TransportLayer = "UDP"
		parsed.Payload = udp.Payload
	} else if icmp4Layer := packet.Layer(layers.LayerTypeICMPv4); icmp4Layer != nil {
		parsed.TransportLayer = "ICMPv4"
	} else if icmp6Layer := packet.Layer(layers.LayerTypeICMPv6); icmp6Layer != nil {
		parsed.TransportLayer = "ICMPv6"
	}

	return parsed, nil
}
