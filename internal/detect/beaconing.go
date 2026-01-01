package detect

import (
	"github.com/ismailtsdln/CapXray/internal/core"
	"github.com/ismailtsdln/CapXray/pkg/models"
)

// BeaconingAnalyzer detects regular interval traffic
type BeaconingAnalyzer struct {
	rules *core.Rules
}

// NewBeaconingAnalyzer creates a new beaconing analyzer
func NewBeaconingAnalyzer(rules *core.Rules) *BeaconingAnalyzer {
	return &BeaconingAnalyzer{rules: rules}
}

// Name returns the analyzer name
func (b *BeaconingAnalyzer) Name() string {
	return "Beaconing"
}

// Analyze processes a flow for beaconing activity
func (b *BeaconingAnalyzer) Analyze(flow *models.Flow) []models.Alert {
	var alerts []models.Alert

	if flow.PacketCount < b.rules.Beaconing.MinHits {
		return nil
	}

	// Simple beaconing logic: Check if packets are sent at regular intervals
	// In a real tool, we would use heartbeats or FFT to find periodicity.
	// For v1, we check the variance of intervals.

	// This requires packet-level timestamps which we don't store in Flow yet
	// for simplicity, but let's assume we have them or use flow duration/count.

	// Placeholder: emit alert if it matches min hits for now
	// alerts = append(alerts, models.Alert{...})

	return alerts
}
