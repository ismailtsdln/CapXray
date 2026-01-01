package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/ismailtsdln/CapXray/internal/core"
)

// Server provides HTTP API for CapXray engine
type Server struct {
	engine     *core.Engine
	port       int
	mu         sync.RWMutex
	httpServer *http.Server
}

// NewServer creates a new API server
func NewServer(engine *core.Engine, port int) *Server {
	return &Server{
		engine: engine,
		port:   port,
	}
}

// Start starts the HTTP server
func (s *Server) Start() error {
	mux := http.NewServeMux()

	// API endpoints
	mux.HandleFunc("/api/flows", s.handleFlows)
	mux.HandleFunc("/api/alerts", s.handleAlerts)
	mux.HandleFunc("/api/stats", s.handleStats)
	mux.HandleFunc("/api/health", s.handleHealth)

	// CORS middleware
	handler := s.enableCORS(mux)

	s.httpServer = &http.Server{
		Addr:         fmt.Sprintf(":%d", s.port),
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}

	color.Green("[*] Starting API server on http://localhost:%d", s.port)
	return s.httpServer.ListenAndServe()
}

// Stop gracefully stops the server
func (s *Server) Stop(ctx context.Context) error {
	if s.httpServer != nil {
		return s.httpServer.Shutdown(ctx)
	}
	return nil
}

// handleFlows returns all reconstructed flows
func (s *Server) handleFlows(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mu.RLock()
	flows := s.engine.Flows
	s.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"flows": flows,
		"count": len(flows),
	})
}

// handleAlerts returns all detected alerts
func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mu.RLock()
	alerts := s.engine.Alerts
	s.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"alerts": alerts,
		"count":  len(alerts),
	})
}

// handleStats returns analysis statistics
func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mu.RLock()
	summary := s.engine.GetSummary()
	flows := s.engine.Flows
	alerts := s.engine.Alerts
	s.mu.RUnlock()

	// Calculate protocol distribution
	protocols := make(map[string]int)
	for _, f := range flows {
		protocols[f.Protocol]++
	}

	// Calculate alert severity distribution
	severities := make(map[string]int)
	for _, a := range alerts {
		severities[a.Severity]++
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"summary":    summary,
		"protocols":  protocols,
		"severities": severities,
		"timestamp":  time.Now().Unix(),
	})
}

// handleHealth returns server health status
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().Unix(),
	})
}

// enableCORS adds CORS headers to responses
func (s *Server) enableCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}
