package tcpscan

import (
	"errors"
	"fmt"
)

var (
	ErrIllegalPortValue  = fmt.Errorf("port value is out of available range %d-%d", MinPort, MaxPort)
	ErrReversedPortRange = errors.New("reversed port range")
	ErrEmptyPortSet      = errors.New("empty port set")
	ErrEmptyHost         = errors.New("empty host")
	ErrEmptyHostSet      = errors.New("empty host set")
	ErrIllegalOption     = errors.New("illegal option")
	ErrNilOption         = errors.New("nil option")
	ErrNoAddresses       = errors.New("no addresses returned")
	ErrInvalidAddr       = errors.New("no valid IP addresses parsed")
)
