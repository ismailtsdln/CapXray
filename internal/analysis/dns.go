package analysis

import (
	"fmt"
	"math"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/ismailtsdln/CapXray/internal/core"
	"github.com/ismailtsdln/CapXray/pkg/models"
)

// DNSAnalyzer analyzes DNS traffic for anomalies and tunneling
type DNSAnalyzer struct {
	rules *core.Rules
}

// NewDNSAnalyzer creates a new DNS analyzer
func NewDNSAnalyzer(rules *core.Rules) *DNSAnalyzer {
	return &DNSAnalyzer{rules: rules}
}

// Name returns the analyzer name
func (d *DNSAnalyzer) Name() string {
	return "DNS"
}

// Analyze processes a flow for DNS specific alerts
func (d *DNSAnalyzer) Analyze(flow *models.Flow) []models.Alert {
	var alerts []models.Alert

	if flow.Protocol != "UDP" && flow.Protocol != "TCP" {
		return nil
	}

	// Basic check for DNS port
	if flow.TargetPort != "53" && flow.SourcePort != "53" {
		return nil
	}

	for _, payload := range flow.Payloads {
		packet := gopacket.NewPacket(payload, layers.LayerTypeDNS, gopacket.Default)
		if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
			dns := dnsLayer.(*layers.DNS)

			// Process DNS Questions
			for _, q := range dns.Questions {
				domain := string(q.Name)
				flow.DNSQueries = append(flow.DNSQueries, domain)

				// Analyze domain length
				if len(domain) > d.rules.DNS.MaxDomainLength {
					alerts = append(alerts, models.Alert{
						Type:        "DNS-Long-Domain",
						Severity:    "Medium",
						FlowID:      flow.ID,
						Description: "Extremely long DNS query detected, possible tunneling or exfiltration",
						Source:      flow.SourceAddress,
						Destination: flow.TargetAddress,
						Protocol:    "DNS",
						Indicators:  []string{domain},
					})
				}

				// Analyze domain entropy
				entropy := calculateEntropy(domain)
				if entropy > d.rules.DNS.EntropyThreshold {
					alerts = append(alerts, models.Alert{
						Type:        "DNS-High-Entropy",
						Severity:    "Medium",
						FlowID:      flow.ID,
						Description: "High entropy DNS query detected, possible encoded exfiltration",
						Source:      flow.SourceAddress,
						Destination: flow.TargetAddress,
						Protocol:    "DNS",
						Indicators:  []string{fmt.Sprintf("%s (entropy: %.2f)", domain, entropy)},
					})
				}
			}

			// Check for NXDOMAIN abuse (if it's a response)
			if dns.ANCount == 0 && dns.ResponseCode == layers.DNSResponseCodeNXDomain {
				alerts = append(alerts, models.Alert{
					Type:        "DNS-NXDOMAIN",
					Severity:    "Low",
					FlowID:      flow.ID,
					Description: "DNS NXDOMAIN response detected",
					Source:      flow.SourceAddress,
					Destination: flow.TargetAddress,
					Protocol:    "DNS",
				})
			}
		}
	}

	return alerts
}

func calculateEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	m := make(map[rune]float64)
	for _, r := range s {
		m[r]++
	}
	var entropy float64
	length := float64(len(s))
	for _, c := range m {
		p := c / length
		entropy -= p * math.Log2(p)
	}
	return entropy
}
