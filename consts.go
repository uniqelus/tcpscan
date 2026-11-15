package tcpscan

import "time"

const (
	MinPort               port          = 1
	MaxPort               port          = 65535
	DefaultConcurrency    int           = 100
	DefaultConnectTimeout time.Duration = 2 * time.Second
)
