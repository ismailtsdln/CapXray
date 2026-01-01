package main

import (
	"context"
	"fmt"

	"github.com/fatih/color"
	"github.com/ismailtsdln/CapXray/internal/analysis"
	"github.com/ismailtsdln/CapXray/internal/api"
	"github.com/ismailtsdln/CapXray/internal/core"
	"github.com/ismailtsdln/CapXray/internal/detect"
	"github.com/spf13/cobra"
)

var serverCmd = &cobra.Command{
	Use:   "server [pcap file]",
	Short: "Start web server with real-time analysis dashboard",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		pcapFile := args[0]
		rulesPath, _ := cmd.Flags().GetString("rules")
		port, _ := cmd.Flags().GetInt("port")

		engine := core.NewEngine()
		rules, err := core.LoadRules(rulesPath)
		if err != nil {
			return fmt.Errorf("failed to load rules: %w", err)
		}
		engine.Rules = rules

		// Register all analyzers
		engine.RegisterAnalyzer(analysis.NewDNSAnalyzer(rules))
		engine.RegisterAnalyzer(analysis.NewHTTPAnalyzer(rules))
		engine.RegisterAnalyzer(analysis.NewTLSAnalyzer(rules))
		engine.RegisterAnalyzer(detect.NewBeaconingAnalyzer(rules))
		engine.RegisterAnalyzer(detect.NewPortscanAnalyzer(rules))
		engine.RegisterAnalyzer(detect.NewTunnelingAnalyzer(rules))
		engine.RegisterAnalyzer(detect.NewAnomalyDetector(rules))

		color.Green("[*] Analyzing PCAP: %s", pcapFile)
		err = engine.Run(context.Background(), pcapFile)
		if err != nil {
			return err
		}

		color.Green("[+] Analysis complete. Starting web server...")

		// Start API server
		server := api.NewServer(engine, port)
		return server.Start()
	},
}

func init() {
	serverCmd.Flags().Int("port", 8080, "HTTP server port")
	rootCmd.AddCommand(serverCmd)
}
