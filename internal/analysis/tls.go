package analysis

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/ismailtsdln/CapXray/internal/core"
	"github.com/ismailtsdln/CapXray/pkg/models"
	"github.com/open-ch/ja3"
)

// TLSAnalyzer analyzes TLS handshakes and generates JA3 fingerprints
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

// Analyze processes a flow for TLS specific alerts and JA3 fingerprinting
func (t *TLSAnalyzer) Analyze(flow *models.Flow) []models.Alert {
	var alerts []models.Alert

	if flow.Protocol != "TCP" {
		return nil
	}

	// Common TLS ports
	if flow.TargetPort != "443" && flow.TargetPort != "8443" && flow.SourcePort != "443" {
		return nil
	}

	for _, payload := range flow.Payloads {
		// Try to compute JA3 fingerprint from the TLS Client Hello
		ja3Hash, ja3String := computeJA3(payload)
		if ja3Hash != "" {
			flow.JA3Fingerprint = ja3Hash

			// Check against known malicious JA3 hashes
			if isSuspiciousJA3(ja3Hash) {
				alerts = append(alerts, models.Alert{
					Type:        "Suspicious-JA3",
					Severity:    "High",
					FlowID:      flow.ID,
					Description: fmt.Sprintf("Suspicious JA3 fingerprint detected: %s", ja3Hash),
					Source:      flow.SourceAddress,
					Destination: flow.TargetAddress,
					Protocol:    "TLS",
					Indicators:  []string{ja3Hash, ja3String},
				})
			}
		}

		// Parse TLS layer for additional analysis
		packet := gopacket.NewPacket(payload, layers.LayerTypeTLS, gopacket.Default)
		if tlsLayer := packet.Layer(layers.LayerTypeTLS); tlsLayer != nil {
			tls := tlsLayer.(*layers.TLS)

			// Check for self-signed or expired certificates in handshake
			for _, record := range tls.Handshake {
				// Future: Parse certificate messages and check validity
				_ = record
			}

			// Extract SNI from Client Hello
			for _, appData := range tls.AppData {
				if sni := extractSNI(appData.Payload); sni != "" {
					flow.TLSHostnames = append(flow.TLSHostnames, sni)
				}
			}
		}
	}

	return alerts
}

// computeJA3 generates JA3 fingerprint from TLS Client Hello
func computeJA3(payload []byte) (string, string) {
	// Use the ja3 library to compute the fingerprint
	j, err := ja3.ComputeJA3FromSegment(payload)
	if err != nil {
		return "", ""
	}

	ja3Hash := j.GetJA3Hash()
	ja3String := j.GetJA3String()

	return ja3Hash, ja3String
}

// isSuspiciousJA3 checks if a JA3 hash is known to be malicious
func isSuspiciousJA3(hash string) bool {
	// Known malicious JA3 hashes (examples from threat intelligence)
	knownMalicious := map[string]string{
		"6734f37431670b3ab4292b8f60f29984": "Trickbot",
		"51c64c77e60f3980eea90869b68c58a8": "Dridex",
		"e7d705a3286e19ea42f587b344ee6865": "Metasploit",
		"ada70206e40642a3e4461f35503241d5": "Cobalt Strike",
	}

	_, exists := knownMalicious[hash]
	return exists
}

// extractSNI extracts Server Name Indication from TLS payload
func extractSNI(payload []byte) string {
	// Simplified SNI extraction
	// In production, this would use proper TLS parsing
	// For now, return empty as gopacket handles this differently
	return ""
}
