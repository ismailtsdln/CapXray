package core

import (
	"context"
	"sync"

	"github.com/ismailtsdln/CapXray/internal/pcap"
	"github.com/ismailtsdln/CapXray/pkg/models"
)

// Analyzer is the interface for all analysis modules
type Analyzer interface {
	Name() string
	Analyze(flow *models.Flow) []models.Alert
}

// Engine is the central analysis coordination unit
type Engine struct {
	Analyzers []Analyzer
	Rules     *Rules
	Flows     []*models.Flow
	Alerts    []models.Alert
	mu        sync.Mutex
}

// NewEngine creates a new Engine instance
func NewEngine() *Engine {
	return &Engine{
		Analyzers: make([]Analyzer, 0),
		Flows:     make([]*models.Flow, 0),
		Alerts:    make([]models.Alert, 0),
	}
}

// RegisterAnalyzer adds an analyzer to the engine
func (e *Engine) RegisterAnalyzer(a Analyzer) {
	e.Analyzers = append(e.Analyzers, a)
}

// Run processes a PCAP file and runs all registered analyzers
func (e *Engine) Run(ctx context.Context, pcapFile string) error {
	loader, err := pcap.NewLoader(pcapFile)
	if err != nil {
		return err
	}
	defer loader.Close()

	parser := pcap.NewParser()
	reconstructor := pcap.NewFlowReconstructor()

	packets, err := loader.Packets()
	if err != nil {
		return err
	}

	for pkt := range packets {
		parsed, err := parser.Parse(pkt)
		if err != nil {
			continue // Skip malformed or unsupported packets
		}
		reconstructor.AddPacket(parsed)
	}

	e.Flows = reconstructor.GetFlows()

	// Concurrent analysis
	var wg sync.WaitGroup
	flowChan := make(chan *models.Flow, len(e.Flows))

	// Start workers
	numWorkers := 4
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for flow := range flowChan {
				for _, analyzer := range e.Analyzers {
					alerts := analyzer.Analyze(flow)
					if len(alerts) > 0 {
						e.mu.Lock()
						e.Alerts = append(e.Alerts, alerts...)
						e.mu.Unlock()
					}
				}
			}
		}()
	}

	// Feed flows to workers
	for _, flow := range e.Flows {
		flowChan <- flow
	}
	close(flowChan)
	wg.Wait()

	return nil
}

// GetSummary returns analysis summary
func (e *Engine) GetSummary() map[string]interface{} {
	return map[string]interface{}{
		"total_flows":    len(e.Flows),
		"total_alerts":   len(e.Alerts),
		"analyzer_count": len(e.Analyzers),
	}
}
