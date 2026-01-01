package pcap

import (
	"fmt"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// Loader handles loading PCAP files
type Loader struct {
	Handle *pcap.Handle
}

// NewLoader creates a new PCAP loader
func NewLoader(filename string) (*Loader, error) {
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		return nil, fmt.Errorf("pcap file does not exist: %s", filename)
	}

	handle, err := pcap.OpenOffline(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open pcap: %w", err)
	}

	return &Loader{Handle: handle}, nil
}

// Close closes the pcap handle
func (l *Loader) Close() {
	if l.Handle != nil {
		l.Handle.Close()
	}
}

// Packets returns a channel of packets from the pcap
func (l *Loader) Packets() (chan gopacket.Packet, error) {
	packetSource := gopacket.NewPacketSource(l.Handle, l.Handle.LinkType())
	return packetSource.Packets(), nil
}
