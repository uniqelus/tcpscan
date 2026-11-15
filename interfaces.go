package tcpscan

import (
	"context"
	"net"
)

type HostResolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
}

type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}
