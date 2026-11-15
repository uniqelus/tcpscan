package tcpscan

import (
	"cmp"
	"errors"
	"fmt"
	"iter"
	"net/netip"
	"slices"
	"strings"
	"time"
)

type host struct {
	raw  string
	addr netip.Addr
}

func newHost(raw string) host {
	h := host{raw: strings.TrimSpace(raw)}
	h.addr, _ = netip.ParseAddr(h.raw)

	return h
}

func (h host) validate() error {
	if h.raw == "" {
		return ErrEmptyHost
	}

	return nil
}

type HostSet struct {
	hosts []host
}

func NewHosts(vals ...string) HostSet {
	hosts := make([]host, len(vals))
	for i, val := range vals {
		hosts[i] = newHost(val)
	}

	return HostSet{hosts: hosts}
}

func (hs HostSet) validate() error {
	if len(hs.hosts) == 0 {
		return ErrEmptyHostSet
	}

	errs := make([]error, 0)
	for _, host := range hs.hosts {
		if err := host.validate(); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

type Port int

func (p Port) validate() error {
	if MinPort > p || p > MaxPort {
		return fmt.Errorf("%w: %d", ErrIllegalPortValue, p)
	}

	return nil
}

type PortSet interface {
	isPortSet()
	validate() error
	portRanges() []PortRange
}

type PortList struct {
	ports []Port
}

func NewPortList(vals ...int) PortList {
	ports := make([]Port, len(vals))
	for i, val := range vals {
		ports[i] = Port(val)
	}

	return PortList{
		ports: ports,
	}
}

func (pl PortList) validate() error {
	if len(pl.ports) == 0 {
		return ErrEmptyPortSet
	}

	errs := make([]error, 0)
	for _, port := range pl.ports {
		if err := port.validate(); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

func (pl PortList) portRanges() []PortRange {
	portRanges := make([]PortRange, len(pl.ports))
	for i, port := range pl.ports {
		portRanges[i] = PortRange{from: port, to: port}
	}

	return portRanges
}

func (pl PortList) isPortSet() {}

type PortRange struct {
	from Port
	to   Port
}

func NewPortRange(from, to int) PortRange {
	return PortRange{
		from: Port(from),
		to:   Port(to),
	}
}

func (pr PortRange) validate() error {
	errs := make([]error, 0)

	if err := pr.from.validate(); err != nil {
		errs = append(errs, err)
	}

	if err := pr.to.validate(); err != nil {
		errs = append(errs, err)
	}

	if pr.from > pr.to {
		errs = append(errs, fmt.Errorf("%w: %d-%d", ErrReversedPortRange, pr.from, pr.to))
	}

	return errors.Join(errs...)
}

func (pr PortRange) portRanges() []PortRange {
	return []PortRange{pr}
}

func (pr PortRange) isPortSet() {}

type PortUnion struct {
	sets []PortSet
}

func NewPortUnion(sets ...PortSet) PortUnion {
	return PortUnion{sets: sets}
}

func (pu PortUnion) validate() error {
	if len(pu.sets) == 0 {
		return ErrEmptyPortSet
	}

	errs := make([]error, 0)
	for _, set := range pu.sets {
		if set == nil {
			return ErrEmptyPortSet
		}

		if err := set.validate(); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

func (pu PortUnion) portRanges() []PortRange {
	portRanges := make([]PortRange, 0)
	for _, set := range pu.sets {
		portRanges = append(portRanges, set.portRanges()...)
	}

	return portRanges
}

func (pu PortUnion) isPortSet() {}

func normalizePortSet(set PortSet) []PortRange {
	if set == nil {
		return []PortRange{}
	}

	portRanges := set.portRanges()
	slices.SortFunc(portRanges, func(a, b PortRange) int {
		if c := cmp.Compare(a.from, b.from); c != 0 {
			return c
		}

		return cmp.Compare(a.to, b.to)
	})

	merged := make([]PortRange, 0, len(portRanges))
	for _, r := range portRanges {
		last := len(merged) - 1
		if last >= 0 && r.from <= merged[last].to+1 {
			merged[last].to = max(merged[last].to, r.to)
			continue
		}
		merged = append(merged, r)
	}

	return merged
}

func allPorts(portRanges []PortRange) iter.Seq[Port] {
	return func(yield func(Port) bool) {
		for _, portRange := range portRanges {
			for i := portRange.from; i <= portRange.to; i++ {
				if !yield(i) {
					return
				}
			}
		}
	}
}

type State string

type endpointGroup struct {
	ip    netip.Addr
	hosts []host
}

type endpointCollector struct {
	groups map[netip.Addr][]host
	order  []netip.Addr
}

func newEndpointCollector(capacity int) *endpointCollector {
	return &endpointCollector{
		groups: make(map[netip.Addr][]host, capacity),
		order:  make([]netip.Addr, 0, capacity),
	}
}

func (c *endpointCollector) add(ip netip.Addr, h host) {
	if ip.IsValid() {
		ip = ip.Unmap()
	}

	existing, exists := c.groups[ip]
	if !exists {
		c.order = append(c.order, ip)
		c.groups[ip] = []host{h}
		return
	}

	for _, item := range existing {
		if strings.EqualFold(item.raw, h.raw) {
			return
		}
	}

	c.groups[ip] = append(existing, h)
}

func (c *endpointCollector) build() []endpointGroup {
	groups := make([]endpointGroup, 0, len(c.order))
	for _, ip := range c.order {
		groups = append(groups, endpointGroup{
			ip:    ip,
			hosts: c.groups[ip],
		})
	}
	return groups
}

type Target struct {
	Addr  netip.AddrPort
	Hosts []string
}

func newTarget(addr netip.AddrPort, hosts []host) Target {
	rawHosts := make([]string, len(hosts))
	for i, h := range hosts {
		rawHosts[i] = h.raw
	}

	return Target{
		Addr:  addr,
		Hosts: rawHosts,
	}
}

type Result struct {
	Host     string
	IP       netip.Addr
	Port     Port
	State    State
	Duration time.Duration
	Err      error
}

func (sr Result) String() string {
	return fmt.Sprintf("%s (%s):%d state=%s duration=%s err=%v",
		sr.Host, sr.IP, sr.Port, sr.State, sr.Duration, sr.Err)
}
