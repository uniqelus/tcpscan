package tcpscan

import (
	"context"
	"net/netip"
)

type TargetSource struct {
	hostSet      HostSet
	portSet      PortSet
	hostResolver HostResolver
}

func NewTargetSource(hostSet HostSet, portSet PortSet, opts ...TargetSourceOption) (*TargetSource, error) {
	options := defaultTargetSourceOptions()
	for _, opt := range opts {
		if err := opt(options); err != nil {
			return nil, err
		}
	}

	if err := hostSet.validate(); err != nil {
		return nil, err
	}

	if err := portSet.validate(); err != nil {
		return nil, err
	}

	return &TargetSource{
		hostSet:      hostSet,
		portSet:      portSet,
		hostResolver: options.hostResolver,
	}, nil
}

func (ts *TargetSource) Targets(ctx context.Context) <-chan Target {
	out := make(chan Target)

	go func() {
		defer close(out)

		portRanges := normalizePortSet(ts.portSet)
		groups := ts.resolveHosts(ctx)

		validGroups := make([]endpointGroup, 0, len(groups))
		for _, g := range groups {
			if !g.ip.IsValid() {
				select {
				case out <- Target{addr: netip.AddrPort{}, hosts: g.hosts}:
				case <-ctx.Done():
					return
				}

				continue
			}

			validGroups = append(validGroups, g)
		}

		for port := range allPorts(portRanges) {
			for _, g := range validGroups {
				target := Target{
					addr:  netip.AddrPortFrom(g.ip, uint16(port)),
					hosts: g.hosts,
				}

				select {
				case out <- target:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	return out
}

func (ts *TargetSource) resolveHosts(ctx context.Context) []endpointGroup {
	collector := newEndpointCollector(len(ts.hostSet.hosts))

	for _, host := range ts.hostSet.hosts {
		if host.addr.IsValid() {
			collector.add(host.addr, host)
			continue
		}

		addrs, err := ts.hostResolver.LookupHost(ctx, host.raw)
		if err != nil || len(addrs) == 0 {
			collector.add(netip.Addr{}, host)
			continue
		}

		resolvedCount := 0
		for _, addr := range addrs {
			ip, err := netip.ParseAddr(addr)
			if err != nil {
				continue
			}
			collector.add(ip, host)
			resolvedCount++
		}

		if resolvedCount == 0 {
			collector.add(netip.Addr{}, host)
		}
	}

	return collector.build()
}
