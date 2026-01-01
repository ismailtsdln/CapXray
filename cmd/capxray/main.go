package main

import (
	"os"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	banner = `
  ____             __  __               
 / ___|__ _ _ __  \ \/ / __ __ _ _   _ 
| |   / _' | '_ \  \  / '__/ _' | | | |
| |__| (_| | |_) | /  \ | | (_| | |_| |
 \____\__,_| .__/ /_/\_\_|  \__,_|\__, |
           |_|                    |___/ 
   Advanced PCAP Analysis Tool
`
)

var rootCmd = &cobra.Command{
	Use:   "capxray",
	Short: "CapXray - High-performance PCAP analysis and threat detection tool",
	Long: `CapXray is an advanced PCAP inspection, traffic analysis, and security detection tool
designed for Blue Teams, SOC Analysts, and DFIR specialists.`,
}

func Execute() {
	color.Cyan(banner)
	if err := rootCmd.Execute(); err != nil {
		color.Red("Error: %v", err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringP("rules", "r", "rules/default.yaml", "Path to rules file")
}

func main() {
	Execute()
}
