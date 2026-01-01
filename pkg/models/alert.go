package models

// Alert represents a detection alert
type Alert struct {
	Type        string   `json:"type"`
	Severity    string   `json:"severity"`
	FlowID      string   `json:"flow_id"`
	Description string   `json:"description"`
	Source      string   `json:"source"`
	Destination string   `json:"destination"`
	Protocol    string   `json:"protocol"`
	Indicators  []string `json:"indicators,omitempty"`
}
