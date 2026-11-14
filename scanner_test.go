package tcpscan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	scanner, err := New()
	require.NoError(t, err)

	assert.Equal(t, defaultConcurrency, scanner.concurrency)
	assert.Equal(t, defaultConnectTimeout, scanner.connectTimeout)
	assert.NotNil(t, scanner.lookup)
	assert.NotNil(t, scanner.dial)
}

func TestNew_Options(t *testing.T) {
	scanner, err := New(WithConcurrency(12), WithConnectTimeout(250*time.Millisecond))
	require.NoError(t, err)

	assert.Equal(t, 12, scanner.concurrency)
	assert.Equal(t, 250*time.Millisecond, scanner.connectTimeout)
}

func TestNew_InvalidOptions(t *testing.T) {
	tests := []struct {
		name    string
		option  Option
		wantErr error
	}{
		{"zero concurrency", WithConcurrency(0), ErrInvalidConcurrency},
		{"negative concurrency", WithConcurrency(-1), ErrInvalidConcurrency},
		{"zero timeout", WithConnectTimeout(0), ErrInvalidConnectTimeout},
		{"negative timeout", WithConnectTimeout(-time.Second), ErrInvalidConnectTimeout},
		{"nil option", nil, ErrNilOption},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner, err := New(tt.option)
			require.Error(t, err)
			assert.Nil(t, scanner)
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestScanner_Scan_Validation(t *testing.T) {
	scanner, err := New()
	require.NoError(t, err)
	scanner.lookup = func(_ context.Context, _ string) ([]string, error) {
		t.Fatal("lookup must not be called for invalid input")
		return nil, nil
	}

	tests := []struct {
		name    string
		hosts   Hosts
		ports   PortSet
		wantErr error
	}{
		{"empty hosts", NewHosts(), NewPorts(80), ErrEmptyHostList},
		{"empty host", NewHosts(""), NewPorts(80), ErrEmptyHost},
		{"nil ports", NewHosts("127.0.0.1"), nil, ErrNilPortSet},
		{"typed nil ports", NewHosts("127.0.0.1"), (*Ports)(nil), ErrNilPortSet},
		{"typed nil range", NewHosts("127.0.0.1"), (*Range)(nil), ErrNilPortSet},
		{"typed nil union", NewHosts("127.0.0.1"), (*Union)(nil), ErrNilPortSet},
		{"empty ports", NewHosts("127.0.0.1"), NewPorts(), ErrEmptyPortList},
		{"invalid port", NewHosts("127.0.0.1"), NewPorts(0), ErrPortOutOfRange},
		{"reversed range", NewHosts("127.0.0.1"), NewRange(100, 1), ErrReversedPortRange},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results, err := scanner.Scan(context.Background(), tt.hosts, tt.ports)
			require.Error(t, err)
			assert.Nil(t, results)
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestScanner_Scan_ResolutionError(t *testing.T) {
	lookupErr := errors.New("lookup failed")
	scanner, err := New()
	require.NoError(t, err)
	scanner.lookup = func(_ context.Context, _ string) ([]string, error) {
		return nil, lookupErr
	}
	scanner.dial = func(_ context.Context, _, _ string) (net.Conn, error) {
		t.Fatal("dial must not be called after a resolution error")
		return nil, nil
	}

	results, err := scanner.Scan(context.Background(), NewHosts("bad.invalid"), NewPorts(80))
	require.Error(t, err)
	assert.Nil(t, results)
	assert.ErrorIs(t, err, ErrHostUnresolvable)
	assert.ErrorIs(t, err, lookupErr)
}

func TestScanner_Scan_Result(t *testing.T) {
	dialErr := errors.New("dial failed")
	scanner, err := New()
	require.NoError(t, err)
	scanner.lookup = func(_ context.Context, host string) ([]string, error) {
		require.Equal(t, "example.com", host)
		return []string{"2001:db8::1"}, nil
	}
	scanner.dial = func(_ context.Context, network, address string) (net.Conn, error) {
		assert.Equal(t, "tcp", network)
		assert.Equal(t, "[2001:db8::1]:443", address)
		return nil, dialErr
	}

	results, err := scanner.Scan(context.Background(), NewHosts("example.com"), NewPorts(443))
	require.NoError(t, err)
	result := receiveSingleResult(t, results)

	assert.Equal(t, "example.com", result.Host)
	assert.Equal(t, netip.MustParseAddr("2001:db8::1"), result.IP)
	assert.Equal(t, uint16(443), result.Port)
	assert.Equal(t, Error, result.State)
	assert.ErrorIs(t, result.Err, dialErr)
	assert.GreaterOrEqual(t, result.Duration, time.Duration(0))
}

func TestScanner_Scan_OpenConnectionIsClosed(t *testing.T) {
	conn := &closeTrackingConn{}
	scanner, err := New()
	require.NoError(t, err)
	scanner.dial = func(_ context.Context, _, _ string) (net.Conn, error) {
		return conn, nil
	}

	results, err := scanner.Scan(context.Background(), NewHosts("127.0.0.1"), NewPorts(80))
	require.NoError(t, err)
	result := receiveSingleResult(t, results)

	assert.Equal(t, Open, result.State)
	assert.NoError(t, result.Err)
	assert.True(t, conn.closed.Load())
}

func TestClassifyError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want PortState
	}{
		{"context canceled", context.Canceled, Canceled},
		{"wrapped context canceled", fmt.Errorf("dial: %w", context.Canceled), Canceled},
		{"deadline exceeded", context.DeadlineExceeded, Timeout},
		{"network timeout", &net.OpError{Err: timeoutError{}}, Timeout},
		{"connection refused", &net.OpError{Err: syscall.ECONNREFUSED}, Closed},
		{"network unreachable", &net.OpError{Err: syscall.ENETUNREACH}, Unreachable},
		{"host unreachable", &net.OpError{Err: syscall.EHOSTUNREACH}, Unreachable},
		{"network down", &net.OpError{Err: syscall.ENETDOWN}, Unreachable},
		{"host down", &net.OpError{Err: syscall.EHOSTDOWN}, Unreachable},
		{"other error", errors.New("connection refused"), Error},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, error2state(context.Background(), tt.err))
		})
	}
}

func TestClassifyError_ParentContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	assert.Equal(t, Canceled, error2state(ctx, context.DeadlineExceeded))
}

func TestScanner_Scan_Timeout(t *testing.T) {
	scanner, err := New(WithConnectTimeout(time.Millisecond))
	require.NoError(t, err)
	scanner.dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}

	results, err := scanner.Scan(context.Background(), NewHosts("127.0.0.1"), NewPorts(80))
	require.NoError(t, err)
	result := receiveSingleResult(t, results)
	assert.Equal(t, Timeout, result.State)
	assert.ErrorIs(t, result.Err, context.DeadlineExceeded)
}

func TestScanner_Scan_StopsSchedulingAfterCancellation(t *testing.T) {
	scanner, err := New(WithConcurrency(2), WithConnectTimeout(time.Minute))
	require.NoError(t, err)
	started := make(chan struct{}, 2)
	scanner.dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
		started <- struct{}{}
		<-ctx.Done()
		return nil, ctx.Err()
	}

	ctx, cancel := context.WithCancel(context.Background())
	results, err := scanner.Scan(ctx, NewHosts("127.0.0.1"), NewRange(1, 20))
	require.NoError(t, err)
	for range 2 {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("connection attempts did not start")
		}
	}
	cancel()

	var collected []Result
	for result := range results {
		collected = append(collected, result)
	}
	require.Len(t, collected, 2)
	for _, result := range collected {
		assert.Equal(t, Canceled, result.State)
		assert.ErrorIs(t, result.Err, context.Canceled)
	}
}

func TestScanner_Scan_LimitsConcurrency(t *testing.T) {
	const concurrency = 3
	const portCount = 12

	scanner, err := New(WithConcurrency(concurrency))
	require.NoError(t, err)
	var active atomic.Int32
	var maximum atomic.Int32
	started := make(chan struct{}, portCount)
	release := make(chan struct{})
	scanner.dial = func(_ context.Context, _, _ string) (net.Conn, error) {
		current := active.Add(1)
		for {
			observed := maximum.Load()
			if current <= observed || maximum.CompareAndSwap(observed, current) {
				break
			}
		}
		started <- struct{}{}
		<-release
		active.Add(-1)
		return nil, errors.New("done")
	}

	results, err := scanner.Scan(context.Background(), NewHosts("127.0.0.1"), NewRange(1, portCount))
	require.NoError(t, err)
	for range concurrency {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("workers did not start")
		}
	}
	close(release)

	collected := collectResults(results)
	assert.Len(t, collected, portCount)
	assert.Equal(t, int32(concurrency), maximum.Load())
}

func TestScanner_Scan_SlowResultReader(t *testing.T) {
	scanner, err := New(WithConcurrency(4))
	require.NoError(t, err)
	scanner.dial = func(_ context.Context, _, _ string) (net.Conn, error) {
		return nil, errors.New("done")
	}

	results, err := scanner.Scan(context.Background(), NewHosts("127.0.0.1"), NewRange(1, 30))
	require.NoError(t, err)
	time.Sleep(10 * time.Millisecond)

	assert.Len(t, collectResults(results), 30)
}

func TestScanner_ConcurrentReuse(t *testing.T) {
	scanner, err := New(WithConcurrency(4))
	require.NoError(t, err)
	scanner.dial = func(_ context.Context, _, _ string) (net.Conn, error) {
		return nil, errors.New("done")
	}

	const scanCount = 4
	var scans sync.WaitGroup
	errs := make(chan error, scanCount)
	scans.Add(scanCount)
	for range scanCount {
		go func() {
			defer scans.Done()
			results, scanErr := scanner.Scan(context.Background(), NewHosts("127.0.0.1"), NewRange(1, 20))
			if scanErr != nil {
				errs <- scanErr
				return
			}
			if count := len(collectResults(results)); count != 20 {
				errs <- fmt.Errorf("got %d results, want 20", count)
				return
			}
			errs <- nil
		}()
	}
	scans.Wait()
	close(errs)
	for scanErr := range errs {
		require.NoError(t, scanErr)
	}
}

func TestScanner_Scan_RealTCPConnection(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	port := listener.Addr().(*net.TCPAddr).Port
	scanner, err := New(WithConnectTimeout(time.Second))
	require.NoError(t, err)
	results, err := scanner.Scan(context.Background(), NewHosts("127.0.0.1"), NewPorts(port))
	require.NoError(t, err)
	result := receiveSingleResult(t, results)

	assert.Equal(t, Open, result.State)
	assert.NoError(t, result.Err)
}

type closeTrackingConn struct {
	net.Conn
	closed atomic.Bool
}

func (c *closeTrackingConn) Close() error {
	c.closed.Store(true)
	return nil
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func receiveSingleResult(t *testing.T, results <-chan Result) Result {
	t.Helper()

	result, ok := <-results
	require.True(t, ok, "result channel is empty")
	_, ok = <-results
	assert.False(t, ok, "result channel contains more than one result")
	return result
}

func collectResults(results <-chan Result) []Result {
	collected := make([]Result, 0)
	for result := range results {
		collected = append(collected, result)
	}
	return collected
}

func TestScanner_Scan_ContextCanceledBeforeScheduling(t *testing.T) {
	scanner, err := New()
	require.NoError(t, err)
	var dialCalled atomic.Bool
	scanner.dial = func(_ context.Context, _, _ string) (net.Conn, error) {
		dialCalled.Store(true)
		return nil, errors.New("unexpected dial")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	results, err := scanner.Scan(ctx, NewHosts("127.0.0.1"), NewRange(1, 100))
	require.NoError(t, err)

	assert.Empty(t, collectResults(results))
	assert.False(t, dialCalled.Load())
}

func TestScanner_Scan_ScansEveryResolvedAddressWithNormalizedPorts(t *testing.T) {
	scanner, err := New(WithConcurrency(6))
	require.NoError(t, err)
	scanner.lookup = func(_ context.Context, _ string) ([]string, error) {
		return []string{"192.0.2.1", "2001:db8::1"}, nil
	}
	dials := make(chan string, 6)
	scanner.dial = func(_ context.Context, _, address string) (net.Conn, error) {
		dials <- address
		return nil, errors.New("done")
	}
	ports := NewUnion(NewPorts(443, 80, 80), NewRange(80, 81))

	results, err := scanner.Scan(context.Background(), NewHosts("example.com"), ports)
	require.NoError(t, err)
	assert.Len(t, collectResults(results), 6)
	close(dials)

	counts := make(map[string]int, 6)
	for address := range dials {
		counts[address]++
	}
	assert.Equal(t, 1, counts["192.0.2.1:80"])
	assert.Equal(t, 1, counts["192.0.2.1:81"])
	assert.Equal(t, 1, counts["192.0.2.1:443"])
	assert.Equal(t, 1, counts["[2001:db8::1]:80"])
	assert.Equal(t, 1, counts["[2001:db8::1]:81"])
	assert.Equal(t, 1, counts["[2001:db8::1]:443"])
}

func TestScanner_Scan_ClosesConnectionReturnedWithError(t *testing.T) {
	conn := &closeTrackingConn{}
	scanner, err := New()
	require.NoError(t, err)
	scanner.dial = func(_ context.Context, _, _ string) (net.Conn, error) {
		return conn, errors.New("dial failed")
	}

	results, err := scanner.Scan(context.Background(), NewHosts("127.0.0.1"), NewPorts(80))
	require.NoError(t, err)
	result := receiveSingleResult(t, results)

	assert.Equal(t, Error, result.State)
	assert.True(t, conn.closed.Load())
}
