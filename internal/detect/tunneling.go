package detect

import (
	"github.com/ismailtsdln/CapXray/internal/core"
	"github.com/ismailtsdln/CapXray/pkg/models"
)

// TunnelingAnalyzer detects DNS or other protocol tunneling
type TunnelingAnalyzer struct {
	rules *core.Rules
}

func NewTunnelingAnalyzer(rules *core.Rules) *TunnelingAnalyzer {
	return &TunnelingAnalyzer{rules: rules}
}

func (t *TunnelingAnalyzer) Name() string {
	return "Tunneling"
}

func (t *TunnelingAnalyzer) Analyze(flow *models.Flow) []models.Alert {
	// Mostly handled by entropy/length in DNS analyzer for v1
	return nil
}
