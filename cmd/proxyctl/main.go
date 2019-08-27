package main

import (
	"fmt"
	"os"

	"github.com/davecgh/go-spew/spew"

	"github.com/spf13/cobra"
	"github.com/sprt/proxyctl"
)

var rootCmd = &cobra.Command{
	Use: "proxyctl",
}

var cmdShow = &cobra.Command{
	Use:   "show <endpoint ID>",
	Short: "Show the active proxy policies on an endpoint",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		endpointID := args[0]
		policies, err := proxyctl.GetPolicies(endpointID)
		if err != nil {
			errorOut(err)
		}
		spew.Dump(policies)
	},
}

func init() {
	rootCmd.AddCommand(cmdShow)
}

func main() {
	rootCmd.Execute()
}

func errorOut(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
