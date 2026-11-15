package tcpscan

import (
	"fmt"
	"net"
	"time"
)

type scannerOptions struct {
	concurrency    int
	connectTimeout time.Duration
	dialer         Dialer
}

func defaultScannerOptions() *scannerOptions {
	return &scannerOptions{
		concurrency:    DefaultScannerConcurrency,
		connectTimeout: DefaultScannerConnectTimeout,
		dialer:         &net.Dialer{},
	}
}

type ScannerOption func(*scannerOptions) error

func WithConcurrency(concurrency int) ScannerOption {
	return func(so *scannerOptions) error {
		if concurrency < 1 {
			return fmt.Errorf("%w: scanner concurrency must be greater than 0, gotten %d", ErrIllegalOption, concurrency)
		}

		so.concurrency = concurrency
		return nil
	}
}

func WithConnectTimeout(timeout time.Duration) ScannerOption {
	return func(so *scannerOptions) error {
		if timeout <= 0 {
			return fmt.Errorf("%w: scanner connect timeout must be greater than 0, gotten %v", ErrIllegalOption, timeout)
		}

		so.connectTimeout = timeout
		return nil
	}
}

func WithDialer(dialer Dialer) ScannerOption {
	return func(so *scannerOptions) error {
		if dialer == nil {
			return fmt.Errorf("%w: nil dialer", ErrIllegalOption)
		}

		so.dialer = dialer
		return nil
	}
}
