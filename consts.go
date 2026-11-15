package tcpscan

import "time"

const (
	MinPort Port = 1
	MaxPort Port = 65535

	DefaultScannerConcurrency    int           = 10
	DefaultScannerConnectTimeout time.Duration = 500 * time.Millisecond

	Open        State = "open"
	Closed      State = "closed"
	Timeout     State = "timeout"
	Unreachable State = "unreachable"
	Canceled    State = "canceled"
	Error       State = "error"
)
