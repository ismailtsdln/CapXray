package models

import (
	"time"

	"github.com/google/gopacket"
)

// Packet represents a normalized packet structure
type Packet struct {
	Timestamp      time.Time
	SourceAddress  string
	TargetAddress  string
	SourcePort     string
	TargetPort     string
	Protocol       string
	Length         int
	Payload        []byte
	LayerType      gopacket.LayerType
	TransportLayer string // TCP, UDP, ICMP
}
