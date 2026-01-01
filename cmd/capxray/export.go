package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/ismailtsdln/CapXray/internal/core"
	"github.com/spf13/cobra"
)

var exportCmd = &cobra.Command{
	Use:   "export [pcap file]",
	Short: "Export analysis results to JSON",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		pcapFile := string(args[0])
		format, _ := cmd.Flags().GetString("format")

		if format != "json" {
			return fmt.Errorf("unsupported format: %s", format)
		}

		engine := core.NewEngine()
		err := engine.Run(context.Background(), pcapFile)
		if err != nil {
			return err
		}

		output := map[string]interface{}{
			"summary": engine.GetSummary(),
			"flows":   engine.Flows,
			"alerts":  engine.Alerts,
		}

		data, err := json.MarshalIndent(output, "", "  ")
		if err != nil {
			return err
		}

		fmt.Println(string(data))
		return nil
	},
}

func init() {
	exportCmd.Flags().String("format", "json", "Output format (json)")
	rootCmd.AddCommand(exportCmd)
}
