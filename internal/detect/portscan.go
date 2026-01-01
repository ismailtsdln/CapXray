package detect

import (
	"github.com/ismailtsdln/CapXray/internal/core"
	"github.com/ismailtsdln/CapXray/pkg/models"
)

// PortscanAnalyzer detects port scanning activity
type PortscanAnalyzer struct {
	rules *core.Rules
}

// NewPortscanAnalyzer creates a new portscan analyzer
func NewPortscanAnalyzer(rules *core.Rules) *PortscanAnalyzer {
	return &PortscanAnalyzer{rules: rules}
}

// Name returns the analyzer name
func (p *PortscanAnalyzer) Name() string {
	return "Portscan"
}

// Analyze processes a flow for port scanning activity
func (p *PortscanAnalyzer) Analyze(flow *models.Flow) []models.Alert {
	// Port scanning is typically across flows, not within a single flow.
	// The Engine should probably handle multi-flow detectors.
	// For now, this is a skeleton.
	return nil
}
