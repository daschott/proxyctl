// Package proxyctl implements a high-level library that allows users to program
// layer-4 proxy policies on Windows through the Host Networking Service (HNS).
package proxyctl

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"os/exec"
	"strconv"

	"github.com/Microsoft/hcsshim/hcn"
)

// LocalSystemSID defines the SID of the permission set known in Windows
// as "Local System". In a sidecar proxy deployment, users will typically run
// the proxy container under that SID, and assign it to the UserSID field of
// the Policy struct, to signify to HNS that traffic originating from that SID
// should not be forwarded to the proxy -- which would create a loop, since
// traffic originating from the proxy would be forwarded back to the proxy.
const LocalSystemSID = "S-1-5-18"

// Protocol refers to a protocol number as defined by the IANA.
// See https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xml.
type Protocol uint8

// TCP is the only protocol supported by the low-level proxy driver so far.
const TCP Protocol = 6

// Policy specifies the proxy and the kind of traffic that will be
// intercepted by the proxy.
type Policy struct {
	// The port the proxy is listening on. (Required)
	ProxyPort uint16

	// Ignore traffic originating from the specified user SID. (Optional)
	UserSID string

	// Only proxy traffic originating from the specified network compartment. (Optional)
	CompartmentID uint32

	// Only proxy traffic originating from the specified address. (Optional)
	LocalAddr net.IP

	// Only proxy traffic destinated to the specified address. (Optional)
	RemoteAddr net.IP

	// The priority of this policy. (Optional)
	// For more info, see https://docs.microsoft.com/en-us/windows/win32/fwp/filter-weight-assignment.
	Priority uint8

	// Only proxy traffic using this protocol. TCP is the only supported
	// protocol for now, and this field defaults to that if left blank. (Optional)
	Protocol Protocol
}

// AddPolicy adds a layer-4 proxy policy to HNS. The endpointID refers to the
// ID of the endpoint as defined by HNS (eg. the GUID output by hnsdiag).
// An error is returned if the policy passed in argument is invalid, or if it
// could not be applied for any reason.
func AddPolicy(hnsEndpointID string, policy Policy) error {
	if err := validatePolicy(policy); err != nil {
		return err
	}

	// TCP is the default protocol and is the only supported one anyway.
	policy.Protocol = TCP

	policySetting := hcn.L4ProxyPolicySetting{
		ProxyType:     hcn.ProxyTypeWFP,
		Port:          strconv.Itoa(int(policy.ProxyPort)),
		UserSID:       policy.UserSID,
		CompartmentID: policy.CompartmentID,
		FilterTuple: hcn.FiveTuple{
			LocalAddresses:  formatIP(policy.LocalAddr),
			RemoteAddresses: formatIP(policy.RemoteAddr),
			Protocols:       strconv.Itoa(int(policy.Protocol)),
			Priority:        uint16(policy.Priority),
		},
	}

	policyJSON, err := json.Marshal(policySetting)
	if err != nil {
		return err
	}

	endpointPolicy := hcn.EndpointPolicy{
		Type:     hcn.L4Proxy,
		Settings: policyJSON,
	}

	request := hcn.PolicyEndpointRequest{
		Policies: []hcn.EndpointPolicy{endpointPolicy},
	}

	endpoint, err := hcn.GetEndpointByID(hnsEndpointID)
	if err != nil {
		return err
	}

	return endpoint.ApplyPolicy(hcn.RequestTypeAdd, request)
}

// ListPolicies returns the proxy policies that are currently active on the
// given endpoint.
func ListPolicies(hnsEndpointID string) ([]Policy, error) {
	hcnPolicies, err := listPolicies(hnsEndpointID)
	if err != nil {
		return nil, err
	}

	var policies []Policy
	for _, hcnPolicy := range hcnPolicies {
		policies = append(policies, hcnPolicyToAPIPolicy(hcnPolicy))
	}

	return policies, nil
}

// ClearPolicies removes all the proxy policies from the specified endpoint.
// It returns the number of policies that were removed, which will be zero
// if an error occurred or if the endpoint did not have any active proxy policies.
func ClearPolicies(hnsEndpointID string) (numRemoved int, err error) {
	policies, err := listPolicies(hnsEndpointID)
	if err != nil {
		return 0, err
	}

	policyReq := hcn.PolicyEndpointRequest{
		Policies: policies,
	}

	policyJSON, err := json.Marshal(policyReq)
	if err != nil {
		return 0, err
	}

	modifyReq := &hcn.ModifyEndpointSettingRequest{
		ResourceType: hcn.EndpointResourceTypePolicy,
		RequestType:  hcn.RequestTypeRemove,
		Settings:     policyJSON,
	}

	return len(policies), hcn.ModifyEndpointSettings(hnsEndpointID, modifyReq)
}

// GetEndpointFromContainer takes a Docker container ID as argument and returns
// the ID of the HNS endpoint to which it is attached. It returns an error if
// the specified container is not attached to any endpoint. Note that there is
// no verification done regarding whether the ID passed as argument belongs
// to an actual container.
func GetEndpointFromContainer(containerID string) (hnsEndpointID string, err error) {
	// XXX: If possible, a better way to do this would be to patch hcsshim
	// so that the endpoints it returns contain the SharedContainers field.

	// Call hnsdiag to get a list of endpoints and the containers they're attached to.

	var hnsOut bytes.Buffer
	hnsCmd := exec.Command("hnsdiag", "list", "endpoints", "-df")
	hnsCmd.Stdout = &hnsOut
	if err = hnsCmd.Run(); err != nil {
		return
	}

	// hnsdiag doesn't return a proper JSON list, instead it's a bunch of
	// objects concatenated to each other, so we have to implement our own
	// parsing logic to split those up. We assume that at least the separate
	// endpoint objects are well-formed.

	scanner := bufio.NewScanner(&hnsOut)

	scanner.Split(func(data []byte, atEOF bool) (advance int, token []byte, err error) {
		endOfEndpoint := []byte("\n}")
		if atEOF && len(data) == 0 {
			// No more data.
			return
		} else if i := bytes.Index(data, endOfEndpoint); i != -1 {
			// '}' right after a newline indicates the end of an endpoint object.
			// We thus advance the scanner past that character and return
			// everything before as a new token.
			advance = i + len(endOfEndpoint) + 1
			return advance, data[:advance], nil
		} else {
			// Request more data.
			return
		}
	})

	for scanner.Scan() {
		type hnsEndpoint struct {
			ID               string
			SharedContainers []string
		}

		var endpoint hnsEndpoint
		err = json.Unmarshal(scanner.Bytes(), &endpoint)
		if err != nil {
			// Assuming HNS returns well-formed JSON objects,
			// if an error happened it was our fault so let's panic.
			panic(err)
		}

		for _, attachedID := range endpoint.SharedContainers {
			if attachedID == containerID {
				return endpoint.ID, nil
			}
		}
	}

	return "", errors.New("could not find an endpoint attached to that container")
}

// listPolicies returns the HCN *proxy* policies that are currently active on the
// given endpoint.
func listPolicies(hnsEndpointID string) ([]hcn.EndpointPolicy, error) {
	endpoint, err := hcn.GetEndpointByID(hnsEndpointID)
	if err != nil {
		return nil, err
	}

	var policies []hcn.EndpointPolicy
	for _, policy := range endpoint.Policies {
		if policy.Type == hcn.L4Proxy {
			policies = append(policies, policy)
		}
	}

	return policies, nil
}

// hcnPolicyToAPIPolicy converts an L4 proxy policy as defined by hcsshim
// to our own API.
func hcnPolicyToAPIPolicy(hcnPolicy hcn.EndpointPolicy) Policy {
	if hcnPolicy.Type != hcn.L4Proxy {
		panic("not an L4 proxy policy")
	}

	// Assuming HNS will never return invalid values from here.

	var hcnPolicySetting hcn.L4ProxyPolicySetting
	_ = json.Unmarshal(hcnPolicy.Settings, &hcnPolicySetting)

	port, _ := strconv.Atoi(hcnPolicySetting.Port)
	protocol, _ := strconv.Atoi(hcnPolicySetting.FilterTuple.Protocols)

	return Policy{
		ProxyPort:     uint16(port),
		UserSID:       hcnPolicySetting.UserSID,
		CompartmentID: hcnPolicySetting.CompartmentID,
		LocalAddr:     net.ParseIP(hcnPolicySetting.FilterTuple.LocalAddresses),
		RemoteAddr:    net.ParseIP(hcnPolicySetting.FilterTuple.RemoteAddresses),
		Priority:      uint8(hcnPolicySetting.FilterTuple.Priority),
		Protocol:      Protocol(protocol),
	}
}

// validatePolicy returns nil iff the provided policy is valid.
// For now it only checks that the port number is nonzero.
func validatePolicy(policy Policy) error {
	if policy.ProxyPort == 0 {
		return errors.New("policy has invalid proxy port number 0")
	}
	return nil
}

// formatIP returns the given address as a string,
// or the empty string if it's nil.
func formatIP(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}
