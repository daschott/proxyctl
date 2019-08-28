# proxyctl

proxyctl is a high-level library and program that allows users to program
layer-4 proxy policies on Windows through the Host Networking Service (HNS).

## Example

The following code sets a proxy policy on the endpoint attached to a known Docker
container, such that:

- Outbound TCP traffic will be redirected through port 8000
- Only if it originates from network compartment 2
- And unless it originates from the Local System SID, which is the proxy itself

```go
dockerContainerID := "3a9b8667e69240afe64e77db0ee4b4056e69278c3d85a9add753eaca6601da93"
hnsEndpointID, _ := proxyctl.GetEndpointFromContainer(dockerContainerID)

proxyPolicy := proxyctl.Policy{
        Port: 8000,
        UserSID: proxyctl.LocalSystemSID,
        CompartmentID: 2,
}

_ = proxyctl.AddPolicy(hnsEndpointID, proxyPolicy)
```

## Current limitations

As of August 27, 2019, these are the limitations of proxyctl (subject to change):

- Only able to proxy outbound TCP traffic.
- Cannot filter specific ports.
