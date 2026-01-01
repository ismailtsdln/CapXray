package analysis

import (
	"github.com/ismailtsdln/CapXray/pkg/models"
)

// StatsAnalyzer collects general PCAP statistics
type StatsAnalyzer struct{}

func NewStatsAnalyzer() *StatsAnalyzer {
	return &StatsAnalyzer{}
}

func (s *StatsAnalyzer) Name() string {
	return "Statistics"
}

func (s *StatsAnalyzer) Analyze(flow *models.Flow) []models.Alert {
	// This analyzer doesn't emit alerts, but could collect top talkers etc.
	// For now, we use it as a placeholder for phase 1 requirements.
	return nil
}
