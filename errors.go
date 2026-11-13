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
)
