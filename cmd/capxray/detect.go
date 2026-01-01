package main

import (
	"context"
	"fmt"
	"os"

	"github.com/fatih/color"
	"github.com/ismailtsdln/CapXray/internal/analysis"
	"github.com/ismailtsdln/CapXray/internal/core"
	"github.com/ismailtsdln/CapXray/internal/detect"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
)

var detectCmd = &cobra.Command{
	Use:   "detect [pcap file]",
	Short: "Run threat detection on a PCAP file",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		pcapFile := string(args[0])
		rulesPath, _ := cmd.Flags().GetString("rules")

		engine := core.NewEngine()
		rules, err := core.LoadRules(rulesPath)
		if err != nil {
			return fmt.Errorf("failed to load rules: %w", err)
		}
		engine.Rules = rules

		// Register analyzers
		engine.RegisterAnalyzer(analysis.NewDNSAnalyzer(rules))
		engine.RegisterAnalyzer(analysis.NewHTTPAnalyzer(rules))
		engine.RegisterAnalyzer(analysis.NewTLSAnalyzer(rules))
		engine.RegisterAnalyzer(detect.NewBeaconingAnalyzer(rules))
		engine.RegisterAnalyzer(detect.NewPortscanAnalyzer(rules))
		engine.RegisterAnalyzer(detect.NewTunnelingAnalyzer(rules))

		color.Green("[*] Running detection on %s...", pcapFile)
		err = engine.Run(context.Background(), pcapFile)
		if err != nil {
			return err
		}

		if len(engine.Alerts) == 0 {
			color.Yellow("[+] No threats detected.")
			return nil
		}

		color.Red("[!] Alerts detected: %d", len(engine.Alerts))
		table := tablewriter.NewWriter(os.Stdout)
		table.Header("Type", "Severity", "Source", "Destination", "Description")
		for _, a := range engine.Alerts {
			table.Append(
				a.Type,
				a.Severity,
				a.Source,
				a.Destination,
				a.Description,
			)
		}

		table.Render()
		return nil
	},
}

func init() {
	rootCmd.AddCommand(detectCmd)
}
