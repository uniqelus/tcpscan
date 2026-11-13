package tcpscan

import (
	"errors"
	"fmt"
)

var (
	ErrPortOutOfRange    = fmt.Errorf("port is out of available range %d-%d", MinPort, MaxPort)
	ErrReversedPortRange = errors.New("port range in a reversed order")
	ErrEmptyPortList     = errors.New("empty port list")
	ErrNilPortSet        = errors.New("nil port set")

	ErrEmptyHost        = errors.New("empty host")
	ErrEmptyHostList    = errors.New("empty host list")
	ErrHostUnresolvable = errors.New("host is unresolvable")

	ErrInvalidConcurrency    = errors.New("concurrency must be greater than zero")
	ErrInvalidConnectTimeout = errors.New("connect timeout must be greater than zero")
	ErrNilOption             = errors.New("nil scanner option")
)
