package tcpscan

import (
	"cmp"
	"errors"
	"fmt"
	"reflect"
	"slices"
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

func isNilPortSet(set PortSet) bool {
	if set == nil {
		return true
	}

	value := reflect.ValueOf(set)
	return value.Kind() == reflect.Pointer && value.IsNil()
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
		if isNilPortSet(set) {
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

// normalize flattens a port set into sorted, non-overlapping ranges:
// duplicate ports and overlapping or adjacent ranges are merged.
func normalize(set PortSet) []Range {
	if set == nil {
		return []Range{}
	}

	ranges := set.ranges()
	slices.SortFunc(ranges, func(a, b Range) int {
		if c := cmp.Compare(a.from, b.from); c != 0 {
			return c
		}
		return cmp.Compare(a.to, b.to)
	})

	merged := make([]Range, 0, len(ranges))
	for _, r := range ranges {
		last := len(merged) - 1
		if last >= 0 && r.from <= merged[last].to+1 {
			merged[last].to = max(merged[last].to, r.to)
			continue
		}
		merged = append(merged, r)
	}

	return merged
}
