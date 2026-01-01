package main

import (
	"context"
	"fmt"
	"os"

	"github.com/fatih/color"
	"github.com/ismailtsdln/CapXray/internal/core"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
)

var statsCmd = &cobra.Command{
	Use:   "stats [pcap file]",
	Short: "Show statistics for a PCAP file",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		pcapFile := string(args[0])

		engine := core.NewEngine()
		err := engine.Run(context.Background(), pcapFile)
		if err != nil {
			return err
		}

		color.Green("[*] Analyzing metrics...")
		table := tablewriter.NewWriter(os.Stdout)
		table.Header("Metric", "Value")
		summary := engine.GetSummary()
		table.Append("Total Flows", fmt.Sprintf("%v", summary["total_flows"]))
		table.Append("Total Alerts", fmt.Sprintf("%v", summary["total_alerts"]))

		// Protocol stats logic (simplified for now)
		protocols := make(map[string]int)
		for _, f := range engine.Flows {
			protocols[f.Protocol]++
		}
		for p, c := range protocols {
			table.Append("Proto: "+p, fmt.Sprintf("%d", c))
		}

		table.Render()
		return nil
	},
}

func init() {
	rootCmd.AddCommand(statsCmd)
}
