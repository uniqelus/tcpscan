package tcpscan

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewHost(t *testing.T) {
	tests := []struct {
		name     string
		raw      string
		wantRaw  string
		wantAddr netip.Addr
	}{
		{"IPv4 literal", "192.168.1.10", "192.168.1.10", netip.MustParseAddr("192.168.1.10")},
		{"IPv6 literal", "::1", "::1", netip.MustParseAddr("::1")},
		{"DNS name", "example.com", "example.com", netip.Addr{}},
		{"surrounding spaces are trimmed", " example.com ", "example.com", netip.Addr{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewHost(tt.raw)

			assert.Equal(t, tt.wantRaw, h.raw)
			assert.Equal(t, tt.wantAddr, h.addr)
		})
	}
}

func TestHost_Validate(t *testing.T) {
	tests := []struct {
		name    string
		host    Host
		wantErr error
	}{
		{"IPv4", NewHost("192.168.1.10"), nil},
		{"IPv6", NewHost("::1"), nil},
		{"DNS name", NewHost("example.com"), nil},
		{"empty host", NewHost(""), ErrEmptyHost},
		{"whitespace only", NewHost("   "), ErrEmptyHost},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.host.validate()
			if tt.wantErr == nil {
				assert.NoError(t, err)
				return
			}

			require.Error(t, err)
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestHosts_Validate(t *testing.T) {
	tests := []struct {
		name    string
		hosts   Hosts
		wantErr error
	}{
		{"valid list", NewHosts("192.168.1.10", "example.com"), nil},
		{"no arguments", NewHosts(), ErrEmptyHostList},
		{"empty list", Hosts{}, ErrEmptyHostList},
		{"empty host in list", NewHosts("example.com", ""), ErrEmptyHost},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.hosts.validate()
			if tt.wantErr == nil {
				assert.NoError(t, err)
				return
			}

			require.Error(t, err)
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestHosts_Validate_ErrorContainsHostIndex(t *testing.T) {
	err := NewHosts("", "example.com", " ").validate()
	require.Error(t, err)

	assert.Contains(t, err.Error(), "host #0")
	assert.Contains(t, err.Error(), "host #2")
}

func TestHosts_Resolve_IPLiteralsSkipLookup(t *testing.T) {
	hosts := NewHosts("192.168.1.10", "::1")
	lookup := func(_ context.Context, host string) ([]string, error) {
		t.Fatalf("lookup must not be called for IP literals, got %q", host)
		return nil, nil
	}

	targets, err := hosts.resolve(context.Background(), lookup)
	require.NoError(t, err)

	want := []target{
		{host: "192.168.1.10", ip: netip.MustParseAddr("192.168.1.10")},
		{host: "::1", ip: netip.MustParseAddr("::1")},
	}
	assert.Equal(t, want, targets)
}

func TestHosts_Resolve_DNSNameResolvesToAllAddresses(t *testing.T) {
	lookup := func(_ context.Context, host string) ([]string, error) {
		require.Equal(t, "example.com", host)
		return []string{"93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"}, nil
	}

	targets, err := NewHosts("example.com").resolve(context.Background(), lookup)
	require.NoError(t, err)

	want := []target{
		{host: "example.com", ip: netip.MustParseAddr("93.184.216.34")},
		{host: "example.com", ip: netip.MustParseAddr("2606:2800:220:1:248:1893:25c8:1946")},
	}
	assert.Equal(t, want, targets)
}

func TestHosts_Resolve_UnresolvableNameDoesNotStopOthers(t *testing.T) {
	lookupErr := errors.New("no such host")
	lookup := func(_ context.Context, host string) ([]string, error) {
		require.Equal(t, "bad.invalid", host)
		return nil, lookupErr
	}

	targets, err := NewHosts("bad.invalid", "10.0.0.1").resolve(context.Background(), lookup)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrHostUnresolvable)
	assert.ErrorIs(t, err, lookupErr)

	want := []target{{host: "10.0.0.1", ip: netip.MustParseAddr("10.0.0.1")}}
	assert.Equal(t, want, targets)
}

func TestHosts_Resolve_EmptyLookupResult(t *testing.T) {
	lookup := func(_ context.Context, _ string) ([]string, error) {
		return nil, nil
	}

	targets, err := NewHosts("example.com").resolve(context.Background(), lookup)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrHostUnresolvable)
	assert.Empty(t, targets)
}

func TestHosts_Resolve_DuplicatesCollapsed(t *testing.T) {
	tests := []struct {
		name  string
		hosts Hosts
		want  []target
	}{
		{
			name:  "same DNS name in different case",
			hosts: NewHosts("Example.COM", "example.com"),
			want:  []target{{host: "Example.COM", ip: netip.MustParseAddr("1.2.3.4")}},
		},
		{
			name:  "repeated IPv4",
			hosts: NewHosts("192.168.1.1", "192.168.1.1"),
			want:  []target{{host: "192.168.1.1", ip: netip.MustParseAddr("192.168.1.1")}},
		},
		{
			name:  "equal IPv6 in different notation",
			hosts: NewHosts("::1", "0:0:0:0:0:0:0:1"),
			want:  []target{{host: "::1", ip: netip.MustParseAddr("::1")}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lookup := func(_ context.Context, _ string) ([]string, error) {
				return []string{"1.2.3.4"}, nil
			}

			targets, err := tt.hosts.resolve(context.Background(), lookup)
			require.NoError(t, err)
			assert.Equal(t, tt.want, targets)
		})
	}
}

func TestHosts_Resolve_DifferentNamesWithSameAddressAreKept(t *testing.T) {
	lookup := func(_ context.Context, _ string) ([]string, error) {
		return []string{"1.2.3.4"}, nil
	}

	targets, err := NewHosts("a.example", "b.example").resolve(context.Background(), lookup)
	require.NoError(t, err)

	want := []target{
		{host: "a.example", ip: netip.MustParseAddr("1.2.3.4")},
		{host: "b.example", ip: netip.MustParseAddr("1.2.3.4")},
	}
	assert.Equal(t, want, targets)
}
