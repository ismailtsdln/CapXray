package models

import (
	"time"
)

// Flow represents a network flow (5-tuple)
type Flow struct {
	ID             string    `json:"id"`
	SourceAddress  string    `json:"src_ip"`
	TargetAddress  string    `json:"dst_ip"`
	SourcePort     string    `json:"src_port"`
	TargetPort     string    `json:"dst_port"`
	Protocol       string    `json:"protocol"`
	StartTime      time.Time `json:"start_time"`
	EndTime        time.Time `json:"end_time"`
	PacketCount    int       `json:"packet_count"`
	ByteCount      int64     `json:"byte_count"`
	Payloads       [][]byte  `json:"-"` // Store payloads for reassembly/analysis
	IsTCP          bool      `json:"is_tcp"`
	TCPFlags       []string  `json:"tcp_flags,omitempty"`
	DNSQueries     []string  `json:"dns_queries,omitempty"`
	HTTPRequests   []string  `json:"http_requests,omitempty"`
	TLSHostnames   []string  `json:"tls_hostnames,omitempty"`
	JA3Fingerprint string    `json:"ja3_fingerprint,omitempty"`
}

// FlowKey returns a string representation of the 5-tuple
func (f *Flow) FlowKey() string {
	return f.SourceAddress + ":" + f.SourcePort + "->" + f.TargetAddress + ":" + f.TargetPort + "[" + f.Protocol + "]"
}
