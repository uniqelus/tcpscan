package tcpscan

import (
	"fmt"
	"time"
)

type scannerOptions struct {
	concurrency    int
	connectTimeout time.Duration
}

func defaultScannerOptions() *scannerOptions {
	return &scannerOptions{
		concurrency:    DefaultConcurrency,
		connectTimeout: DefaultConnectTimeout,
	}
}

type ScannerOption func(*scannerOptions) error

func WithConcurrency(concurrency int) ScannerOption {
	return func(so *scannerOptions) error {
		if concurrency < 1 {
			return fmt.Errorf("%w: %d", ErrInvalidConcurrency, concurrency)
		}

		so.concurrency = concurrency
		return nil
	}
}

func WithConnectTimeout(timeout time.Duration) ScannerOption {
	return func(so *scannerOptions) error {
		if timeout <= 0 {
			return fmt.Errorf("%w: %s", ErrInvalidConnectTimeout, timeout)
		}

		so.connectTimeout = timeout
		return nil
	}
}
