package tcpscan

import (
	"errors"
	"fmt"
)

type port int

func (p port) validate() error {
	if MinPort > p || MaxPort < p {
		return fmt.Errorf("%w: %d", ErrPortOutOfRange, p)
	}

	return nil
}

type PortSet interface {
	validate() error
	ranges() []Range
}

// Port list
type Ports struct {
	values []port
}

func NewPorts(vals ...int) Ports {
	values := make([]port, len(vals))
	for i, val := range vals {
		values[i] = port(val)
	}

	return Ports{values: values}
}

func (ps Ports) validate() error {
	if len(ps.values) == 0 {
		return ErrEmptyPortList
	}

	errs := make([]error, 0)
	for _, p := range ps.values {
		if err := p.validate(); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

func (ps Ports) ranges() []Range {
	ranges := make([]Range, len(ps.values))
	for i, p := range ps.values {
		ranges[i] = Range{from: p, to: p}
	}

	return ranges
}

// port range
type Range struct {
	from port
	to   port
}

func NewRange(from, to int) Range {
	return Range{
		from: port(from),
		to:   port(to),
	}
}

func (r Range) validate() error {
	if err := r.from.validate(); err != nil {
		return err
	}

	if err := r.to.validate(); err != nil {
		return err
	}

	if r.from > r.to {
		return fmt.Errorf("%w: %d-%d", ErrReversedPortRange, r.from, r.to)
	}

	return nil
}

func (r Range) ranges() []Range {
	return []Range{r}
}

// union of any number of port list & port range & another unions
type Union []PortSet

func NewUnion(sets ...PortSet) Union {
	return Union(sets)
}

func (u Union) validate() error {
	if len(u) == 0 {
		return ErrEmptyPortList
	}

	errs := make([]error, 0)
	for i, set := range u {
		if set == nil {
			errs = append(errs, fmt.Errorf("set #%d: %w", i, ErrNilPortSet))
			continue
		}

		if err := set.validate(); err != nil {
			errs = append(errs, fmt.Errorf("set #%d: %w", i, err))
		}
	}

	return errors.Join(errs...)
}

func (u Union) ranges() []Range {
	ranges := make([]Range, 0)
	for _, set := range u {
		ranges = append(ranges, set.ranges()...)
	}

	return ranges
}
