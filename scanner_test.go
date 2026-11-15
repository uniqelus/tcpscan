package tcpscan_test

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/uniqelus/tcpscan"
	"github.com/uniqelus/tcpscan/mocks"
)

func collectScanResults(t *testing.T, results <-chan tcpscan.Result) []tcpscan.Result {
	t.Helper()

	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()

	var collected []tcpscan.Result
	for {
		select {
		case result, ok := <-results:
			if !ok {
				return collected
			}

			collected = append(collected, result)
		case <-timer.C:
			t.Fatal("timed out waiting for the result channel to close")
			return nil
		}
	}
}

func TestScanner_Scan(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		targets       []tcpscan.Target
		dialErr       error
		expectedState tcpscan.State
	}{
		"open port and multiple hosts": {
			targets: []tcpscan.Target{
				{
					Addr:  netip.MustParseAddrPort("192.0.2.1:80"),
					Hosts: []string{"example.com", "alias.test"},
				},
			},
			expectedState: tcpscan.Open,
		},
		"closed port": {
			targets: []tcpscan.Target{
				{
					Addr:  netip.MustParseAddrPort("192.0.2.1:81"),
					Hosts: []string{"192.0.2.1"},
				},
			},
			dialErr:       syscall.ECONNREFUSED,
			expectedState: tcpscan.Closed,
		},
		"timeout": {
			targets: []tcpscan.Target{
				{
					Addr:  netip.MustParseAddrPort("192.0.2.1:82"),
					Hosts: []string{"192.0.2.1"},
				},
			},
			dialErr:       context.DeadlineExceeded,
			expectedState: tcpscan.Timeout,
		},
		"unreachable": {
			targets: []tcpscan.Target{
				{
					Addr:  netip.MustParseAddrPort("192.0.2.1:83"),
					Hosts: []string{"192.0.2.1"},
				},
			},
			dialErr:       syscall.ENETUNREACH,
			expectedState: tcpscan.Unreachable,
		},
		"canceled dial": {
			targets: []tcpscan.Target{
				{
					Addr:  netip.MustParseAddrPort("192.0.2.1:84"),
					Hosts: []string{"192.0.2.1"},
				},
			},
			dialErr:       context.Canceled,
			expectedState: tcpscan.Canceled,
		},
		"unexpected dial error": {
			targets: []tcpscan.Target{
				{
					Addr:  netip.MustParseAddrPort("192.0.2.1:85"),
					Hosts: []string{"192.0.2.1"},
				},
			},
			dialErr:       errors.New("dial failed"),
			expectedState: tcpscan.Error,
		},
		"invalid target": {
			targets: []tcpscan.Target{
				{Hosts: []string{"unresolved.test"}},
			},
			expectedState: tcpscan.Error,
		},
		"multiple targets": {
			targets: []tcpscan.Target{
				{
					Addr:  netip.MustParseAddrPort("192.0.2.1:80"),
					Hosts: []string{"192.0.2.1"},
				},
				{
					Addr:  netip.MustParseAddrPort("[2001:db8::1]:443"),
					Hosts: []string{"2001:db8::1"},
				},
			},
			expectedState: tcpscan.Open,
		},
	}

	for testName, testCase := range tests {
		t.Run(testName, func(t *testing.T) {
			dialer := mocks.NewDialer(t)
			for _, target := range testCase.targets {
				if !target.Addr.IsValid() {
					continue
				}

				dialer.EXPECT().
					DialContext(mock.Anything, "tcp", target.Addr.String()).
					Return(nil, testCase.dialErr).
					Once()
			}

			scanner, err := tcpscan.NewScanner(
				tcpscan.WithConcurrency(1),
				tcpscan.WithConnectTimeout(time.Second),
				tcpscan.WithDialer(dialer),
			)
			require.NoError(t, err)

			targets := make(chan tcpscan.Target, len(testCase.targets))
			for _, target := range testCase.targets {
				targets <- target
			}
			close(targets)

			actual := collectScanResults(t, scanner.Scan(context.Background(), targets))

			expectedCount := 0
			for _, target := range testCase.targets {
				expectedCount += len(target.Hosts)
			}
			require.Len(t, actual, expectedCount)

			resultIndex := 0
			for _, target := range testCase.targets {
				for _, host := range target.Hosts {
					result := actual[resultIndex]
					resultIndex++

					expectedState := testCase.expectedState
					expectedErr := testCase.dialErr
					if !target.Addr.IsValid() {
						expectedState = tcpscan.Error
						expectedErr = tcpscan.ErrInvalidAddr
					}

					assert.Equal(t, host, result.Host)
					assert.Equal(t, target.Addr.Addr(), result.IP)
					assert.Equal(t, tcpscan.Port(target.Addr.Port()), result.Port)
					assert.Equal(t, expectedState, result.State)
					assert.GreaterOrEqual(t, result.Duration, time.Duration(0))
					if expectedErr == nil {
						assert.NoError(t, result.Err)
					} else {
						assert.ErrorIs(t, result.Err, expectedErr)
					}
				}
			}
		})
	}
}

func TestScanner_ScanCancelsActiveDial(t *testing.T) {
	t.Parallel()

	dialer := mocks.NewDialer(t)
	dialStarted := make(chan struct{})
	dialer.EXPECT().
		DialContext(mock.Anything, "tcp", "192.0.2.1:80").
		RunAndReturn(func(ctx context.Context, _, _ string) (net.Conn, error) {
			close(dialStarted)
			<-ctx.Done()
			return nil, ctx.Err()
		}).
		Once()

	scanner, err := tcpscan.NewScanner(
		tcpscan.WithConcurrency(1),
		tcpscan.WithDialer(dialer),
	)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	targets := make(chan tcpscan.Target, 1)
	targets <- tcpscan.Target{
		Addr:  netip.MustParseAddrPort("192.0.2.1:80"),
		Hosts: []string{"192.0.2.1"},
	}
	close(targets)

	results := scanner.Scan(ctx, targets)
	select {
	case <-dialStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the dial to start")
	}

	cancel()

	actual := collectScanResults(t, results)
	for _, result := range actual {
		assert.Equal(t, tcpscan.Canceled, result.State)
	}
}

func TestScanner_ScanStopsWaitingForTargetsOnCancellation(t *testing.T) {
	t.Parallel()

	dialer := mocks.NewDialer(t)
	scanner, err := tcpscan.NewScanner(
		tcpscan.WithConcurrency(1),
		tcpscan.WithDialer(dialer),
	)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	targets := make(chan tcpscan.Target)
	results := scanner.Scan(ctx, targets)

	cancel()

	assert.Empty(t, collectScanResults(t, results))
}
