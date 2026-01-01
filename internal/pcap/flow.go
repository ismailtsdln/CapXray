package pcap

import (
	"sync"

	"github.com/ismailtsdln/CapXray/pkg/models"
)

// FlowReconstructor manages the state of active flows
type FlowReconstructor struct {
	mu    sync.RWMutex
	flows map[string]*models.Flow
}

// NewFlowReconstructor creates a new flow reconstructor
func NewFlowReconstructor() *FlowReconstructor {
	return &FlowReconstructor{
		flows: make(map[string]*models.Flow),
	}
}

// AddPacket adds a packet to its corresponding flow
func (f *FlowReconstructor) AddPacket(p *models.Packet) {
	key := f.generateKey(p)

	f.mu.Lock()
	defer f.mu.Unlock()

	flow, exists := f.flows[key]
	if !exists {
		flow = &models.Flow{
			ID:            key,
			SourceAddress: p.SourceAddress,
			TargetAddress: p.TargetAddress,
			SourcePort:    p.SourcePort,
			TargetPort:    p.TargetPort,
			Protocol:      p.TransportLayer,
			StartTime:     p.Timestamp,
			EndTime:       p.Timestamp,
			PacketCount:   0,
			ByteCount:     0,
			IsTCP:         p.TransportLayer == "TCP",
		}
		f.flows[key] = flow
	}

	flow.EndTime = p.Timestamp
	flow.PacketCount++
	flow.ByteCount += int64(p.Length)
	if len(p.Payload) > 0 {
		flow.Payloads = append(flow.Payloads, p.Payload)
	}
}

// GetFlows returns all reconstructed flows
func (f *FlowReconstructor) GetFlows() []*models.Flow {
	f.mu.RLock()
	defer f.mu.RUnlock()

	result := make([]*models.Flow, 0, len(f.flows))
	for _, flow := range f.flows {
		result = append(result, flow)
	}
	return result
}

func (f *FlowReconstructor) generateKey(p *models.Packet) string {
	// Normalized key (src:port -> dst:port)
	// For bi-directional flow, we could sort IPs/Ports to group into one flow
	// but requirement says src:port -> dst:port + protocol
	return p.SourceAddress + ":" + p.SourcePort + "->" + p.TargetAddress + ":" + p.TargetPort + "[" + p.TransportLayer + "]"
}
