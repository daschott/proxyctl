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

	// Ignore traffic originating from that user SID. (Optional)
	UserSID string

	// Only proxy traffic hitting this network compartment. (Optional)
	CompartmentID uint32

	// Only proxy traffic which local address matches the given IP. (Optional)
	LocalAddr net.IP

	// Only proxy traffic which remote address matches the given IP. (Optional)
	RemoteAddr net.IP

	// The priority of this policy. (Optional)
	// For more info, see https://docs.microsoft.com/en-us/windows/win32/fwp/filter-weight-assignment.
	Priority uint8

	// Only proxy traffic matching this protocol. TCP is the only supported
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

// GetPolicies returns the proxy policies that are currently active on the
// given endpoint.
func GetPolicies(hnsEndpointID string) ([]Policy, error) {
	endpoint, err := hcn.GetEndpointByID(hnsEndpointID)
	if err != nil {
		return nil, err
	}

	var policies []Policy
	for _, hcnPolicy := range endpoint.Policies {
		if hcnPolicy.Type == hcn.L4Proxy {
			policies = append(policies, hcnPolicyToAPIPolicy(hcnPolicy))
		}
	}

	return policies, nil
}

// GetEndpointFromContainer takes a Docker container ID as argument and returns
// the ID of the HNS endpoint to which it is attached. It returns an error if
// the specified container is not attached to any endpoint. Note that there is
// no verification done regarding whether the ID passed as argument belongs
// to an actual container.
func GetEndpointFromContainer(containerID string) (hnsEndpointID string, err error) {
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

	scanEndpointObjects := func(data []byte, atEOF bool) (advance int, token []byte, err error) {
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
	}

	scanner := bufio.NewScanner(&hnsOut)
	scanner.Split(scanEndpointObjects)

	for scanner.Scan() {
		type hnsEndpoint struct {
			ID               string
			SharedContainers []string
		}

		var endpoint hnsEndpoint
		err = json.Unmarshal(scanner.Bytes(), &endpoint)
		if err != nil {
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

// hcnPolicyToAPIPolicy converts an L4 proxy policy as defined by hcsshim
// to our own API.
func hcnPolicyToAPIPolicy(hcnPolicy hcn.EndpointPolicy) Policy {
	if hcnPolicy.Type != hcn.L4Proxy {
		panic("not an L4 proxy policy")
	}

	var hcnPolicySetting hcn.L4ProxyPolicySetting
	json.Unmarshal(hcnPolicy.Settings, &hcnPolicySetting)

	// Assuming HNS will never return invalid values here.
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
		return errors.New("policy has invalid port number 0")
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
