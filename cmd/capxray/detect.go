package main

import (
	"context"
	"fmt"
	"os"

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

		fmt.Printf("[*] Running detection on %s...\n", pcapFile)
		err = engine.Run(context.Background(), pcapFile)
		if err != nil {
			return err
		}

		if len(engine.Alerts) == 0 {
			fmt.Println("[+] No threats detected.")
			return nil
		}

		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"Type", "Severity", "Source", "Destination", "Description"})
		for _, a := range engine.Alerts {
			table.Append([]string{
				a.Type,
				a.Severity,
				a.Source,
				a.Destination,
				a.Description,
			})
		}

		table.Render()
		return nil
	},
}

func init() {
	rootCmd.AddCommand(detectCmd)
}
