package tcpscan

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPort_Validate(t *testing.T) {
	tests := []struct {
		name    string
		port    port
		wantErr error
	}{
		{"valid well-known port", 80, nil},
		{"valid lower boundary", MinPort, nil},
		{"valid upper boundary", MaxPort, nil},
		{"zero port", 0, ErrPortOutOfRange},
		{"negative port", -1, ErrPortOutOfRange},
		{"above max", 65536, ErrPortOutOfRange},
		{"far above max", 100000, ErrPortOutOfRange},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.port.validate()
			if tt.wantErr == nil {
				assert.NoError(t, err)
				return
			}

			require.Error(t, err)
			assert.ErrorIs(t, err, tt.wantErr)
			assert.Contains(t, err.Error(), fmt.Sprintf("%d", tt.port))
		})
	}
}

func TestNewPorts(t *testing.T) {
	ports := NewPorts(22, 80, 443)

	assert.Equal(t, []port{22, 80, 443}, ports.values)
}

func TestPorts_Validate(t *testing.T) {
	tests := []struct {
		name    string
		ports   Ports
		wantErr error
	}{
		{"valid list", NewPorts(1, 80, 65535), nil},
		{"duplicates are allowed", NewPorts(80, 80, 443), nil},
		{"port below range", NewPorts(0, 80), ErrPortOutOfRange},
		{"port above range", NewPorts(80, 65536), ErrPortOutOfRange},
		{"zero value is empty", Ports{}, ErrEmptyPortList},
		{"no arguments", NewPorts(), ErrEmptyPortList},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.ports.validate()
			if tt.wantErr == nil {
				assert.NoError(t, err)
				return
			}

			require.Error(t, err)
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestPorts_Validate_JoinsAllErrors(t *testing.T) {
	err := NewPorts(-100, 80, 70000).validate()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPortOutOfRange)
	assert.Len(t, strings.Split(err.Error(), "\n"), 2)
}

func TestPorts_Ranges(t *testing.T) {
	tests := []struct {
		name  string
		ports Ports
		want  []Range
	}{
		{
			name:  "single port",
			ports: NewPorts(80),
			want:  []Range{{from: 80, to: 80}},
		},
		{
			name:  "multiple ports",
			ports: NewPorts(22, 80, 443),
			want: []Range{
				{from: 22, to: 22},
				{from: 80, to: 80},
				{from: 443, to: 443},
			},
		},
		{
			name:  "duplicates are kept",
			ports: NewPorts(80, 80),
			want:  []Range{{from: 80, to: 80}, {from: 80, to: 80}},
		},
		{
			name:  "empty list",
			ports: NewPorts(),
			want:  []Range{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.ports.ranges())
		})
	}
}

func TestNewRange(t *testing.T) {
	r := NewRange(8000, 8080)

	assert.Equal(t, Range{from: 8000, to: 8080}, r)
}

func TestRange_Validate(t *testing.T) {
	tests := []struct {
		name    string
		r       Range
		wantErr error
	}{
		{"valid range", NewRange(1, 1000), nil},
		{"single port range", NewRange(80, 80), nil},
		{"full range", NewRange(1, 65535), nil},
		{"reversed range", NewRange(1000, 1), ErrReversedPortRange},
		{"from below range", NewRange(0, 1000), ErrPortOutOfRange},
		{"to above range", NewRange(80, 65536), ErrPortOutOfRange},
		{"both out of range", NewRange(-10, 70000), ErrPortOutOfRange},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.r.validate()
			if tt.wantErr == nil {
				assert.NoError(t, err)
				return
			}

			require.Error(t, err)
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestRange_Ranges(t *testing.T) {
	r := NewRange(8000, 8080)

	assert.Equal(t, []Range{{from: 8000, to: 8080}}, r.ranges())
}

func TestUnion_Validate(t *testing.T) {
	tests := []struct {
		name    string
		union   Union
		wantErr error
	}{
		{
			"valid mixed union",
			NewUnion(NewPorts(22, 80), NewRange(8000, 8080), NewUnion(NewRange(443, 443))),
			nil,
		},
		{"empty union", NewUnion(), ErrEmptyPortList},
		{"nil set", NewUnion(NewPorts(80), nil), ErrNilPortSet},
		{"invalid inner set", NewUnion(NewPorts(80), NewRange(100, 1)), ErrReversedPortRange},
		{"invalid port in list", NewUnion(NewPorts(0)), ErrPortOutOfRange},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.union.validate()
			if tt.wantErr == nil {
				assert.NoError(t, err)
				return
			}

			require.Error(t, err)
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestUnion_Validate_ErrorContainsSetIndex(t *testing.T) {
	err := NewUnion(NewPorts(80), nil, NewRange(100, 1)).validate()
	require.Error(t, err)

	assert.Contains(t, err.Error(), "set #1")
	assert.Contains(t, err.Error(), "set #2")
	assert.ErrorIs(t, err, ErrNilPortSet)
	assert.ErrorIs(t, err, ErrReversedPortRange)
}

func TestUnion_Ranges(t *testing.T) {
	union := NewUnion(
		NewPorts(22, 80),
		NewRange(8000, 8002),
		NewUnion(NewRange(443, 443), NewPorts(9090)),
	)

	want := []Range{
		{from: 22, to: 22},
		{from: 80, to: 80},
		{from: 8000, to: 8002},
		{from: 443, to: 443},
		{from: 9090, to: 9090},
	}

	assert.Equal(t, want, union.ranges())
}

func TestPortSet_ImpliesInterface(t *testing.T) {
	sets := []PortSet{
		NewPorts(80),
		NewRange(1, 100),
		NewUnion(NewPorts(80)),
	}

	for _, set := range sets {
		assert.NoError(t, set.validate())
		assert.NotEmpty(t, set.ranges())
	}
}
