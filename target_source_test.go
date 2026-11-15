package tcpscan_test

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/uniqelus/tcpscan"
	"github.com/uniqelus/tcpscan/mocks"
)

type lookupResult struct {
	addresses []string
	err       error
}

func TestTargetSource_Targets(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		hostSet  tcpscan.HostSet
		portSet  tcpscan.PortSet
		lookups  map[string]lookupResult
		expected []tcpscan.Target
	}{
		"normalizes ports and preserves host order": {
			hostSet: tcpscan.NewHosts(
				"192.0.2.1",
				"2001:db8::1",
			),
			portSet: tcpscan.NewPortUnion(
				tcpscan.NewPortList(443, 80),
				tcpscan.NewPortRange(80, 81),
			),
			expected: []tcpscan.Target{
				{
					Addr:  netip.MustParseAddrPort("192.0.2.1:80"),
					Hosts: []string{"192.0.2.1"},
				},
				{
					Addr:  netip.MustParseAddrPort("[2001:db8::1]:80"),
					Hosts: []string{"2001:db8::1"},
				},
				{
					Addr:  netip.MustParseAddrPort("192.0.2.1:81"),
					Hosts: []string{"192.0.2.1"},
				},
				{
					Addr:  netip.MustParseAddrPort("[2001:db8::1]:81"),
					Hosts: []string{"2001:db8::1"},
				},
				{
					Addr:  netip.MustParseAddrPort("192.0.2.1:443"),
					Hosts: []string{"192.0.2.1"},
				},
				{
					Addr:  netip.MustParseAddrPort("[2001:db8::1]:443"),
					Hosts: []string{"2001:db8::1"},
				},
			},
		},
		"scans all DNS addresses and groups aliases": {
			hostSet: tcpscan.NewHosts(
				"example.com",
				"alias.test",
				"example.com",
			),
			portSet: tcpscan.NewPortList(80),
			lookups: map[string]lookupResult{
				"example.com": {
					addresses: []string{"192.0.2.1", "2001:db8::1"},
				},
				"alias.test": {
					addresses: []string{"192.0.2.1"},
				},
			},
			expected: []tcpscan.Target{
				{
					Addr:  netip.MustParseAddrPort("192.0.2.1:80"),
					Hosts: []string{"example.com", "alias.test"},
				},
				{
					Addr:  netip.MustParseAddrPort("[2001:db8::1]:80"),
					Hosts: []string{"example.com"},
				},
			},
		},
		"emits an unresolved host once": {
			hostSet: tcpscan.NewHosts(
				"unresolved.test",
				"192.0.2.1",
			),
			portSet: tcpscan.NewPortList(80, 443),
			lookups: map[string]lookupResult{
				"unresolved.test": {
					err: errors.New("host not found"),
				},
			},
			expected: []tcpscan.Target{
				{Hosts: []string{"unresolved.test"}},
				{
					Addr:  netip.MustParseAddrPort("192.0.2.1:80"),
					Hosts: []string{"192.0.2.1"},
				},
				{
					Addr:  netip.MustParseAddrPort("192.0.2.1:443"),
					Hosts: []string{"192.0.2.1"},
				},
			},
		},
		"emits hosts without valid resolved addresses": {
			hostSet: tcpscan.NewHosts(
				"empty.test",
				"invalid.test",
			),
			portSet: tcpscan.NewPortList(80),
			lookups: map[string]lookupResult{
				"empty.test":   {},
				"invalid.test": {addresses: []string{"not-an-ip"}},
			},
			expected: []tcpscan.Target{
				{Hosts: []string{"empty.test", "invalid.test"}},
			},
		},
	}

	for testName, testCase := range tests {
		t.Run(testName, func(t *testing.T) {
			hostResolver := mocks.NewHostResolver(t)
			for host, result := range testCase.lookups {
				hostResolver.EXPECT().
					LookupHost(mock.Anything, host).
					Return(result.addresses, result.err)
			}

			source, err := tcpscan.NewTargetSource(
				testCase.hostSet,
				testCase.portSet,
				tcpscan.WithHostResolver(hostResolver),
			)
			require.NoError(t, err)

			var actual []tcpscan.Target
			for target := range source.Targets(context.Background()) {
				actual = append(actual, target)
			}

			assert.Equal(t, testCase.expected, actual)
		})
	}
}
