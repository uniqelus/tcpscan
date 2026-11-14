package tcpscan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"syscall"
	"time"
)

const (
	defaultConcurrency    = 100
	defaultConnectTimeout = 2 * time.Second
)

// PortState describes the outcome of a TCP connection attempt.
type PortState string

const (
	// Open means that a TCP connection was established.
	Open PortState = "open"
	// Closed means that the target explicitly refused the connection.
	Closed PortState = "closed"
	// Timeout means that the connection attempt exceeded the configured timeout.
	Timeout PortState = "timeout"
	// Unreachable means that the target host or network was unreachable.
	Unreachable PortState = "unreachable"
	// Canceled means that the connection attempt was canceled through its context.
	Canceled PortState = "canceled"
	// Error means that the connection attempt failed for another reason.
	Error PortState = "error"
)

// Result contains the outcome of scanning one port on one resolved address.
type Result struct {
	Host     string
	IP       netip.Addr
	Port     uint16
	State    PortState
	Duration time.Duration
	Err      error
}

// Option configures a Scanner.
type Option func(*Scanner) error

// WithConcurrency sets the maximum number of simultaneous connection attempts.
func WithConcurrency(concurrency int) Option {
	return func(s *Scanner) error {
		if concurrency < 1 {
			return fmt.Errorf("%w: %d", ErrInvalidConcurrency, concurrency)
		}

		s.concurrency = concurrency
		return nil
	}
}

// WithConnectTimeout sets the timeout for each individual connection attempt.
func WithConnectTimeout(timeout time.Duration) Option {
	return func(s *Scanner) error {
		if timeout <= 0 {
			return fmt.Errorf("%w: %s", ErrInvalidConnectTimeout, timeout)
		}

		s.connectTimeout = timeout
		return nil
	}
}

type dialContextFunc func(ctx context.Context, network, address string) (net.Conn, error)

// Scanner performs concurrent TCP Connect scans. It is safe for concurrent use.
type Scanner struct {
	concurrency    int
	connectTimeout time.Duration
	lookup         lookupFunc
	dial           dialContextFunc
}

// New creates a Scanner with the supplied options.
func New(options ...Option) (*Scanner, error) {
	s := &Scanner{
		concurrency:    defaultConcurrency,
		connectTimeout: defaultConnectTimeout,
		lookup:         net.DefaultResolver.LookupHost,
		dial:           (&net.Dialer{}).DialContext,
	}

	for i, option := range options {
		if option == nil {
			return nil, fmt.Errorf("option #%d: %w", i, ErrNilOption)
		}
		if err := option(s); err != nil {
			return nil, fmt.Errorf("option #%d: %w", i, err)
		}
	}

	return s, nil
}

type scanJob struct {
	target target
	port   port
}

// Scan resolves hosts and starts scanning ports. Validation and resolution
// errors are returned synchronously. The result channel is closed after all
// started connection attempts finish. After context cancellation no new jobs
// are scheduled; results for already started attempts have state Canceled when
// their dial reports context cancellation.
func (s *Scanner) Scan(ctx context.Context, hosts Hosts, set PortSet) (<-chan Result, error) {
	if err := hosts.validate(); err != nil {
		return nil, err
	}
	if isNilPortSet(set) {
		return nil, ErrNilPortSet
	}
	if err := set.validate(); err != nil {
		return nil, err
	}

	targets, err := hosts.resolve(ctx, s.lookup)
	if err != nil {
		return nil, err
	}

	ranges := normalize(set)

	jobs := s.generateScanJobs(ctx, targets, ranges)
	results := s.runScanPool(ctx, jobs)

	return results, nil
}

func (s *Scanner) generateScanJobs(ctx context.Context, targets []target, ranges []Range) <-chan scanJob {
	out := make(chan scanJob)

	go func() {
		defer close(out)

		for _, t := range targets {
			for _, r := range ranges {
				for curr := r.from; curr <= r.to; curr++ {
					if ctx.Err() != nil {
						return
					}

					select {
					case out <- scanJob{target: t, port: curr}:
					case <-ctx.Done():
						return
					}
				}
			}
		}
	}()

	return out
}

func (s *Scanner) runScanPool(ctx context.Context, jobs <-chan scanJob) chan Result {
	out := make(chan Result, s.concurrency)

	wg := &sync.WaitGroup{}
	wg.Add(s.concurrency)

	for range s.concurrency {
		go func() {
			defer wg.Done()

			for job := range jobs {
				out <- s.scan(ctx, job)
			}
		}()
	}

	go func() {
		wg.Wait()
		close(out)
	}()

	return out
}

func (s *Scanner) scan(ctx context.Context, job scanJob) Result {
	result := Result{
		Host:  job.target.host,
		IP:    job.target.ip,
		Port:  uint16(job.port),
		State: Error,
	}

	dialCtx, cancel := context.WithTimeout(ctx, s.connectTimeout)
	defer cancel()

	address := net.JoinHostPort(job.target.ip.String(), strconv.Itoa(int(job.port)))

	started := time.Now()
	conn, err := s.dial(dialCtx, "tcp", address)
	result.Duration = time.Since(started)

	if conn != nil {
		_ = conn.Close()
	}

	if err == nil {
		result.State = Open
		return result
	}

	result.Err = err
	result.State = error2state(ctx, err)
	return result
}

func error2state(ctx context.Context, err error) PortState {
	if ctx.Err() != nil || errors.Is(err, context.Canceled) {
		return Canceled
	}

	var netErr net.Error
	if errors.Is(err, context.DeadlineExceeded) ||
		(errors.As(err, &netErr) && netErr.Timeout()) {
		return Timeout
	}

	if errors.Is(err, syscall.ECONNREFUSED) {
		return Closed
	}

	if errors.Is(err, syscall.ENETUNREACH) ||
		errors.Is(err, syscall.EHOSTUNREACH) ||
		errors.Is(err, syscall.ENETDOWN) ||
		errors.Is(err, syscall.EHOSTDOWN) {
		return Unreachable
	}

	return Error
}
