package proxyctl

import (
	"encoding/json"
	"errors"
	"net"
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
	Port uint16

	// Ignore traffic originating from that user SID. (Optional)
	UserSID string

	// Only proxy traffic hitting this network compartment. (Optional)
	CompartmentID uint32

	// Only proxy traffic which local address matches the given IP. (Optional)
	LocalAddr net.IP

	// Only proxy traffic which remote address matches the given IP. (Optional)
	RemoteAddr net.IP

	// The priority of this policy. (Optional)
	// See https://docs.microsoft.com/en-us/windows/win32/fwp/filter-weight-assignment.
	Priority uint8

	// Only proxy traffic matching this protocol. TCP is the only supported
	// protocol for now, and this field defaults to that if left blank. (Optional)
	Protocol Protocol
}

// AddPolicy adds a layer-4 proxy policy to HNS. The endpointID refers to the
// ID of the endpoint as defined by HNS (eg. the GUID output by hnsdiag).
// An error is returned if the policy passed in argument is invalid, or if it
// couldn't be applied for any reason.
func AddPolicy(endpointID string, policy Policy) error {
	if err := validatePolicy(policy); err != nil {
		return err
	}

	// TCP is the default protocol and is the only supported one anyway.
	policy.Protocol = TCP

	policySetting := hcn.L4ProxyPolicySetting{
		ProxyType:     hcn.ProxyTypeWFP,
		Port:          strconv.Itoa(int(policy.Port)),
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

	endpoint, err := hcn.GetEndpointByID(endpointID)
	if err != nil {
		panic(err)
	}

	return endpoint.ApplyPolicy(hcn.RequestTypeAdd, request)
}

// GetPolicies returns the proxy policies that are currently active on the
// given endpoint.
func GetPolicies(endpointID string) ([]Policy, error) {
	endpoint, err := hcn.GetEndpointByID(endpointID)
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

// hcnPolicyToAPIPolicy converts an L4 proxy policy as defined by hcsshim
// to our own API.
func hcnPolicyToAPIPolicy(hcnPolicy hcn.EndpointPolicy) Policy {
	if hcnPolicy.Type != hcn.L4Proxy {
		panic("not an L4 proxy policy")
	}

	var hcnPolicySetting hcn.L4ProxyPolicySetting
	json.Unmarshal(hcnPolicy.Settings, &hcnPolicySetting)

	port, _ := strconv.Atoi(hcnPolicySetting.Port)
	protocol, _ := strconv.Atoi(hcnPolicySetting.FilterTuple.Protocols)

	return Policy{
		Port:          uint16(port),
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
	if policy.Port == 0 {
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
