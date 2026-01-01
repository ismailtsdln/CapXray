package analysis

import (
	"bufio"
	"bytes"
	"net/http"
	"strings"

	"github.com/ismailtsdln/CapXray/internal/core"
	"github.com/ismailtsdln/CapXray/pkg/models"
)

// HTTPAnalyzer analyzes HTTP traffic for suspicious activity
type HTTPAnalyzer struct {
	rules *core.Rules
}

// NewHTTPAnalyzer creates a new HTTP analyzer
func NewHTTPAnalyzer(rules *core.Rules) *HTTPAnalyzer {
	return &HTTPAnalyzer{rules: rules}
}

// Name returns the analyzer name
func (h *HTTPAnalyzer) Name() string {
	return "HTTP"
}

// Analyze processes a flow for HTTP specific alerts
func (h *HTTPAnalyzer) Analyze(flow *models.Flow) []models.Alert {
	var alerts []models.Alert

	if flow.Protocol != "TCP" {
		return nil
	}

	for _, payload := range flow.Payloads {
		// Attempt to parse as HTTP Request
		req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(payload)))
		if err == nil {
			flow.HTTPRequests = append(flow.HTTPRequests, req.Method+" "+req.URL.String())

			// Check for suspicious User-Agents
			ua := req.UserAgent()
			for _, suspiciousUA := range h.rules.HTTP.SuspiciousUAs {
				if strings.Contains(strings.ToLower(ua), strings.ToLower(suspiciousUA)) {
					alerts = append(alerts, models.Alert{
						Type:        "Suspicious-User-Agent",
						Severity:    "High",
						FlowID:      flow.ID,
						Description: "Suspicious HTTP User-Agent detected: " + ua,
						Source:      flow.SourceAddress,
						Destination: flow.TargetAddress,
						Protocol:    "HTTP",
						Indicators:  []string{ua},
					})
				}
			}

			// Check for basic credentials in headers (simplified)
			if auth := req.Header.Get("Authorization"); auth != "" {
				if strings.HasPrefix(strings.ToLower(auth), "basic ") {
					alerts = append(alerts, models.Alert{
						Type:        "Cleartext-Credentials",
						Severity:    "Medium",
						FlowID:      flow.ID,
						Description: "HTTP Basic Authentication detected over cleartext",
						Source:      flow.SourceAddress,
						Destination: flow.TargetAddress,
						Protocol:    "HTTP",
					})
				}
			}
			continue
		}

		// Attempt to parse as HTTP Response (optional for alerts, but good for metadata)
		_, err = http.ReadResponse(bufio.NewReader(bytes.NewReader(payload)), nil)
		if err == nil {
			// Could track 404s, etc.
		}
	}

	return alerts
}
