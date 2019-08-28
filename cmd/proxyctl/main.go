package main

import (
	"fmt"
	"net"
	"os"

	"github.com/davecgh/go-spew/spew"
	"github.com/spf13/cobra"
	"github.com/sprt/proxyctl"
)

var rootCmd = &cobra.Command{
	Use: "proxyctl.exe",
}

// Flags for the "add" command
var (
	proxyPort     uint16
	userSID       string
	compartmentID uint32
	localAddr     net.IP
	remoteAddr    net.IP
	priority      uint8
	protocol      proxyctl.Protocol
)

var cmdAdd = &cobra.Command{
	Use:   "add <HNS endpoint ID>",
	Short: "Add a proxy policy to an endpoint.",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		endpointID := args[0]
		policy := proxyctl.Policy{
			ProxyPort:     proxyPort,
			UserSID:       userSID,
			CompartmentID: compartmentID,
			LocalAddr:     localAddr,
			RemoteAddr:    remoteAddr,
			Priority:      priority,
		}

		err := proxyctl.AddPolicy(endpointID, policy)
		if err != nil {
			errorOut(err)
		}

		fmt.Println("Successfully added the policy")
	},
}

var cmdClear = &cobra.Command{
	Use:   "clear <HNS endpoint ID>",
	Short: "Remove all proxy policies from an endpoint.",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		endpointID := args[0]
		numRemoved, err := proxyctl.ClearPolicies(endpointID)
		if err != nil {
			errorOut(err)
		}
		fmt.Println("Removed", numRemoved, "policies")
	},
}

var cmdList = &cobra.Command{
	Use:   "list <HNS endpoint ID>",
	Short: "List the active proxy policies on an endpoint.",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		endpointID := args[0]
		policies, err := proxyctl.ListPolicies(endpointID)
		if err != nil {
			errorOut(err)
		}
		spew.Dump(policies)
	},
}

var cmdLookup = &cobra.Command{
	Use:   "lookup <docker container ID>",
	Short: "Report the ID of the HNS endpoint to which the specified container is attached.",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		containerID := args[0]
		hnsEndpointID, err := proxyctl.GetEndpointFromContainer(containerID)
		if err != nil {
			errorOut(err)
		}
		fmt.Println(hnsEndpointID)
	},
}

func init() {
	rootCmd.AddCommand(cmdAdd)
	rootCmd.AddCommand(cmdClear)
	rootCmd.AddCommand(cmdList)
	rootCmd.AddCommand(cmdLookup)
}

func main() {
	// Flags for the "add" command
	cmdAdd.Flags().Uint16VarP(&proxyPort, "port", "p", 0, "port the proxy is listening on")
	cmdAdd.MarkFlagRequired("port")
	cmdAdd.Flags().StringVar(&userSID, "usersid", "", "ignore traffic originating from the specified user SID")
	cmdAdd.Flags().Uint32Var(&compartmentID, "compartment", 0, "only proxy traffic originating from the specified network compartment")
	cmdAdd.Flags().IPVar(&localAddr, "localaddr", nil, "only proxy traffic originating from the specified address")
	cmdAdd.Flags().IPVar(&remoteAddr, "remoteaddr", nil, "only proxy traffic destinated to the specified address")
	cmdAdd.Flags().Uint8Var(&priority, "priority", 0, "the priority of this policy")

	rootCmd.Execute()
}

func errorOut(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
