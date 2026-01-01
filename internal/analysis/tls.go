package analysis

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/ismailtsdln/CapXray/internal/core"
	"github.com/ismailtsdln/CapXray/pkg/models"
)

// TLSAnalyzer analyzes TLS handshakes
type TLSAnalyzer struct {
	rules *core.Rules
}

// NewTLSAnalyzer creates a new TLS analyzer
func NewTLSAnalyzer(rules *core.Rules) *TLSAnalyzer {
	return &TLSAnalyzer{rules: rules}
}

// Name returns the analyzer name
func (t *TLSAnalyzer) Name() string {
	return "TLS"
}

// Analyze processes a flow for TLS specific alerts
func (t *TLSAnalyzer) Analyze(flow *models.Flow) []models.Alert {
	var alerts []models.Alert

	if flow.Protocol != "TCP" {
		return nil
	}

	for _, payload := range flow.Payloads {
		packet := gopacket.NewPacket(payload, layers.LayerTypeTLS, gopacket.Default)
		if tlsLayer := packet.Layer(layers.LayerTypeTLS); tlsLayer != nil {
			tls := tlsLayer.(*layers.TLS)

			for range tls.Handshake {
				// Simplified JA3/SNI extraction logic
				// Note: Full JA3 requires precise field extraction which gopacket's TLS layer handles partially.
				// For v1, we focus on SNI and basic cert checks if available.

				// This is a placeholder for actual TLS logic as gopacket's TLS layer is quite complex
				// and often requires custom parsers for handshake messages.

				// We'll emit an alert if we see self-signed certs (conceptually)
				// Actual implementation would need to parse the Certificate message
			}
		}
	}

	return alerts
}
