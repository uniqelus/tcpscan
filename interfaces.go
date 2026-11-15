package tcpscan

import "context"

type HostResolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
}
