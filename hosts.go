package tcpscan

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// Host is a scan target: an IPv4/IPv6 address or a DNS name.
type Host struct {
	raw  string
	addr netip.Addr // valid when raw is an IP literal
}

func NewHost(raw string) Host {
	h := Host{raw: strings.TrimSpace(raw)}
	h.addr, _ = netip.ParseAddr(h.raw)

	return h
}

func (h Host) validate() error {
	if h.raw == "" {
		return ErrEmptyHost
	}

	return nil
}

// Host list
type Hosts []Host

func NewHosts(raws ...string) Hosts {
	hosts := make(Hosts, len(raws))
	for i, raw := range raws {
		hosts[i] = NewHost(raw)
	}

	return hosts
}

func (hs Hosts) validate() error {
	if len(hs) == 0 {
		return ErrEmptyHostList
	}

	errs := make([]error, 0)
	for i, h := range hs {
		if err := h.validate(); err != nil {
			errs = append(errs, fmt.Errorf("host #%d: %w", i, err))
		}
	}

	return errors.Join(errs...)
}

// target is a concrete IP address to scan, keeping the original user input.
type target struct {
	host string
	ip   netip.Addr
}

type lookupFunc func(ctx context.Context, host string) ([]string, error)

// resolve maps hosts to targets: IP literals are used as is, DNS names are
// resolved via lookup and every resolved address becomes a separate target.
// Duplicate targets (repeated names in any case, equal IPs in different
// notation) are collapsed. Unresolvable names are reported in the returned
// error while the remaining hosts still produce targets.
func (hs Hosts) resolve(ctx context.Context, lookup lookupFunc) ([]target, error) {
	targets := make([]target, 0, len(hs))
	seen := make(map[string]struct{}, len(hs))
	errs := make([]error, 0)

	for _, h := range hs {
		key := strings.ToLower(h.raw)
		if h.addr.IsValid() {
			key = h.addr.Unmap().String()
		}
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}

		if h.addr.IsValid() {
			targets = append(targets, target{host: h.raw, ip: h.addr.Unmap()})
			continue
		}

		addrs, err := lookup(ctx, h.raw)
		if err != nil {
			errs = append(errs, fmt.Errorf("%w: %s: %w", ErrHostUnresolvable, h.raw, err))
			continue
		}
		if len(addrs) == 0 {
			errs = append(errs, fmt.Errorf("%w: %s", ErrHostUnresolvable, h.raw))
			continue
		}

		for _, addr := range addrs {
			ip, err := netip.ParseAddr(addr)
			if err != nil {
				continue
			}
			targets = append(targets, target{host: h.raw, ip: ip.Unmap()})
		}
	}

	return targets, errors.Join(errs...)
}
