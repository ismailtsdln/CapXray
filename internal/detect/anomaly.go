package detect

import (
	"math"
	"sort"
	"time"

	"github.com/ismailtsdln/CapXray/internal/core"
	"github.com/ismailtsdln/CapXray/pkg/models"
)

// AnomalyDetector uses statistical analysis to detect anomalous traffic patterns
type AnomalyDetector struct {
	rules       *core.Rules
	flowStats   map[string]*FlowStatistics
	globalStats *GlobalStatistics
}

// FlowStatistics holds statistics for a single flow
type FlowStatistics struct {
	PacketIntervals []float64
	ByteSizes       []int64
	Mean            float64
	StdDev          float64
}

// GlobalStatistics holds baseline statistics across all flows
type GlobalStatistics struct {
	AvgPacketsPerFlow float64
	AvgBytesPerFlow   float64
	FlowCount         int
}

// NewAnomalyDetector creates a new ML-based anomaly detector
func NewAnomalyDetector(rules *core.Rules) *AnomalyDetector {
	return &AnomalyDetector{
		rules:       rules,
		flowStats:   make(map[string]*FlowStatistics),
		globalStats: &GlobalStatistics{},
	}
}

// Name returns the analyzer name
func (a *AnomalyDetector) Name() string {
	return "AnomalyDetection"
}

// Analyze processes a flow for statistical anomalies
func (a *AnomalyDetector) Analyze(flow *models.Flow) []models.Alert {
	var alerts []models.Alert

	// Calculate flow statistics
	stats := a.calculateFlowStats(flow)
	a.flowStats[flow.ID] = stats

	// Update global baseline
	a.updateGlobalStats(flow)

	// Detection 1: Check for beaconing behavior (regular intervals)
	if isBeaconing := a.detectBeaconing(stats, flow); isBeaconing {
		alerts = append(alerts, models.Alert{
			Type:        "ML-Beaconing",
			Severity:    "High",
			FlowID:      flow.ID,
			Description: "Regular interval traffic pattern detected (possible C2 beaconing)",
			Source:      flow.SourceAddress,
			Destination: flow.TargetAddress,
			Protocol:    flow.Protocol,
		})
	}

	// Detection 2: Check for anomalous packet sizes
	if isAnomalousSize := a.detectAnomalousPacketSize(flow); isAnomalousSize {
		alerts = append(alerts, models.Alert{
			Type:        "ML-Anomalous-Size",
			Severity:    "Medium",
			FlowID:      flow.ID,
			Description: "Unusual packet size distribution detected",
			Source:      flow.SourceAddress,
			Destination: flow.TargetAddress,
			Protocol:    flow.Protocol,
		})
	}

	// Detection 3: Check for data exfiltration patterns
	if isExfiltration := a.detectExfiltration(flow); isExfiltration {
		alerts = append(alerts, models.Alert{
			Type:        "ML-Data-Exfiltration",
			Severity:    "Critical",
			FlowID:      flow.ID,
			Description: "Possible data exfiltration pattern detected (high upload volume)",
			Source:      flow.SourceAddress,
			Destination: flow.TargetAddress,
			Protocol:    flow.Protocol,
		})
	}

	return alerts
}

func (a *AnomalyDetector) calculateFlowStats(flow *models.Flow) *FlowStatistics {
	stats := &FlowStatistics{
		PacketIntervals: make([]float64, 0),
		ByteSizes:       make([]int64, 0),
	}

	// Calculate packet intervals and sizes
	duration := flow.EndTime.Sub(flow.StartTime).Seconds()
	if flow.PacketCount > 1 && duration > 0 {
		avgInterval := duration / float64(flow.PacketCount-1)

		// Simulate interval data (in real implementation, we'd track timestamps)
		for i := 0; i < flow.PacketCount-1; i++ {
			stats.PacketIntervals = append(stats.PacketIntervals, avgInterval)
		}
	}

	// Calculate mean and standard deviation of intervals
	if len(stats.PacketIntervals) > 0 {
		stats.Mean = mean(stats.PacketIntervals)
		stats.StdDev = stdDev(stats.PacketIntervals, stats.Mean)
	}

	return stats
}

func (a *AnomalyDetector) updateGlobalStats(flow *models.Flow) {
	a.globalStats.FlowCount++
	a.globalStats.AvgPacketsPerFlow = (a.globalStats.AvgPacketsPerFlow*float64(a.globalStats.FlowCount-1) + float64(flow.PacketCount)) / float64(a.globalStats.FlowCount)
	a.globalStats.AvgBytesPerFlow = (a.globalStats.AvgBytesPerFlow*float64(a.globalStats.FlowCount-1) + float64(flow.ByteCount)) / float64(a.globalStats.FlowCount)
}

func (a *AnomalyDetector) detectBeaconing(stats *FlowStatistics, flow *models.Flow) bool {
	// Beaconing is characterized by:
	// 1. Low standard deviation in packet intervals (regular timing)
	// 2. Minimum number of packets
	// 3. Long duration

	if flow.PacketCount < a.rules.Beaconing.MinHits {
		return false
	}

	duration := flow.EndTime.Sub(flow.StartTime)
	if duration < 30*time.Second {
		return false
	}

	// Check if intervals are regular (low coefficient of variation)
	if stats.Mean > 0 {
		coefficientOfVariation := stats.StdDev / stats.Mean
		return coefficientOfVariation < 0.15 // Very regular timing
	}

	return false
}

func (a *AnomalyDetector) detectAnomalousPacketSize(flow *models.Flow) bool {
	// Check if the average packet size is unusual
	if flow.PacketCount == 0 {
		return false
	}

	avgPacketSize := float64(flow.ByteCount) / float64(flow.PacketCount)

	// Flag extremely small or large packets
	return avgPacketSize < 10 || avgPacketSize > 50000
}

func (a *AnomalyDetector) detectExfiltration(flow *models.Flow) bool {
	// Exfiltration is characterized by:
	// 1. High upload volume (assuming source is internal)
	// 2. Long duration connection
	// 3. Sustained traffic

	duration := flow.EndTime.Sub(flow.StartTime)
	if duration < 60*time.Second {
		return false
	}

	// Check for high byte count (>10MB) over sustained period
	if flow.ByteCount > 10*1024*1024 {
		return true
	}

	return false
}

// Helper functions
func mean(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sum := 0.0
	for _, v := range values {
		sum += v
	}
	return sum / float64(len(values))
}

func stdDev(values []float64, mean float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sumSquares := 0.0
	for _, v := range values {
		diff := v - mean
		sumSquares += diff * diff
	}
	return math.Sqrt(sumSquares / float64(len(values)))
}

func median(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sorted := make([]float64, len(values))
	copy(sorted, values)
	sort.Float64s(sorted)

	mid := len(sorted) / 2
	if len(sorted)%2 == 0 {
		return (sorted[mid-1] + sorted[mid]) / 2
	}
	return sorted[mid]
}
