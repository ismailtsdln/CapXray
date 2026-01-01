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

var flowsCmd = &cobra.Command{
	Use:   "flows [pcap file]",
	Short: "List reconstructed flows from a PCAP file",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		pcapFile := string(args[0])

		engine := core.NewEngine()
		err := engine.Run(context.Background(), pcapFile)
		if err != nil {
			return err
		}

		color.Green("[*] Listing reconstructed flows...")
		table := tablewriter.NewWriter(os.Stdout)
		table.Header("ID", "Source", "Destination", "Proto", "Pkts", "Bytes")
		for _, f := range engine.Flows {
			table.Append(
				f.ID,
				fmt.Sprintf("%s:%s", f.SourceAddress, f.SourcePort),
				fmt.Sprintf("%s:%s", f.TargetAddress, f.TargetPort),
				f.Protocol,
				fmt.Sprintf("%d", f.PacketCount),
				fmt.Sprintf("%d", f.ByteCount),
			)
		}

		table.Render()
		return nil
	},
}

func init() {
	rootCmd.AddCommand(flowsCmd)
}
