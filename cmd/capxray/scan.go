package main

import (
	"context"
	"fmt"

	"github.com/ismailtsdln/CapXray/internal/core"
	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:   "scan [pcap file]",
	Short: "Scan a PCAP file for general analysis",
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

		fmt.Printf("[*] Scanning %s...\n", pcapFile)
		err = engine.Run(context.Background(), pcapFile)
		if err != nil {
			return err
		}

		summary := engine.GetSummary()
		fmt.Printf("[+] Scan complete. Total flows: %v, Alerts: %v\n", summary["total_flows"], summary["total_alerts"])
		return nil
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)
}
