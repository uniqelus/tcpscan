package tcpscan

import (
	"fmt"
	"net"
)

type targetSourceOptions struct {
	hostResolver HostResolver
}

func defaultTargetSourceOptions() *targetSourceOptions {
	return &targetSourceOptions{
		hostResolver: net.DefaultResolver,
	}
}

type TargetSourceOption func(*targetSourceOptions) error

func WithHostResolver(hostResolver HostResolver) TargetSourceOption {
	return func(tso *targetSourceOptions) error {
		if hostResolver == nil {
			return fmt.Errorf("%w: host resolver is nil", ErrIllegalOption)
		}

		tso.hostResolver = hostResolver
		return nil
	}
}
