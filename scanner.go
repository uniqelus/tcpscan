package tcpscan

import (
	"context"
	"errors"
	"net"
	"sync"
	"syscall"
	"time"
)

type Scanner struct {
	concurrency    int
	connectTimeout time.Duration
	dialer         Dialer
}

func NewScanner(opts ...ScannerOption) (*Scanner, error) {
	options := defaultScannerOptions()
	for _, opt := range opts {
		if err := opt(options); err != nil {
			return nil, err
		}
	}

	return &Scanner{
		concurrency:    options.concurrency,
		connectTimeout: options.connectTimeout,
		dialer:         options.dialer,
	}, nil
}

func (s *Scanner) Scan(ctx context.Context, targets <-chan Target) <-chan Result {
	out := make(chan Result)

	wg := &sync.WaitGroup{}
	wg.Add(s.concurrency)

	for range s.concurrency {
		go func() {
			defer wg.Done()

			for {
				select {
				case target, ok := <-targets:
					if !ok {
						return
					}

					if ctx.Err() != nil {
						return
					}

					results := s.scanTarget(ctx, target)
					for _, result := range results {
						select {
						case out <- result:
						case <-ctx.Done():
							return
						}
					}

				case <-ctx.Done():
					return
				}
			}

		}()
	}

	go func() {
		wg.Wait()
		close(out)
	}()

	return out
}

func (s *Scanner) scanTarget(ctx context.Context, target Target) []Result {
	if !target.addr.IsValid() {
		return resultsForTarget(target, Error, 0, ErrInvalidAddr)
	}

	dialCtx, cancel := context.WithTimeout(ctx, s.connectTimeout)
	defer cancel()

	started := time.Now()
	conn, err := s.dialer.DialContext(dialCtx, "tcp", target.addr.String())
	duration := time.Since(started)

	if conn != nil {
		_ = conn.Close()
	}

	state := Open
	if err != nil {
		state = classifyError(ctx, err)
	}

	return resultsForTarget(target, state, duration, err)
}

func resultsForTarget(target Target, state State, duration time.Duration, err error) []Result {
	results := make([]Result, len(target.hosts))
	for i, host := range target.hosts {
		results[i] = Result{
			Host:     host.raw,
			IP:       target.addr.Addr(),
			Port:     Port(target.addr.Port()),
			State:    state,
			Duration: duration,
			Err:      err,
		}
	}

	return results
}

func classifyError(ctx context.Context, err error) State {
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
