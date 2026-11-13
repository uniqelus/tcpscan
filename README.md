# tcpscan

`tcpscan` is a Go package for concurrent TCP Connect scanning of one or more IPv4 addresses, IPv6 addresses, or DNS names. It uses only Go's standard networking APIs at runtime and does not require raw sockets or elevated privileges.

## Installation

```sh
go get github.com/uniqelus/tcpscan
```

The module requires Go 1.25.5 or newer.

## Usage

```go
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/uniqelus/tcpscan"
)

func main() {
	scanner, err := tcpscan.New(
		tcpscan.WithConcurrency(100),
		tcpscan.WithConnectTimeout(500*time.Millisecond),
	)
	if err != nil {
		log.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ports := tcpscan.NewUnion(
		tcpscan.NewPorts(22, 80, 443),
		tcpscan.NewRange(8000, 8010),
	)
	results, err := scanner.Scan(
		ctx,
		tcpscan.NewHosts("127.0.0.1", "::1", "example.com"),
		ports,
	)
	if err != nil {
		log.Fatal(err)
	}

	// Always drain the channel, including after cancellation.
	for result := range results {
		fmt.Printf(
			"%s (%s):%d state=%s duration=%s err=%v\n",
			result.Host,
			result.IP,
			result.Port,
			result.State,
			result.Duration,
			result.Err,
		)
	}
}
```

A scan produces one result for every started host/address/port check. Result order is not guaranteed because checks run concurrently. Callers should consume results until the channel is closed; abandonment of the channel can leave workers waiting to deliver their results.

## Public API

### Scanner

- `New(options ...Option) (*Scanner, error)` creates a scanner. Defaults are 100 concurrent connection attempts and a 2-second timeout per attempt.
- `WithConcurrency(n int)` sets the maximum number of simultaneous connection attempts. `n` must be positive.
- `WithConnectTimeout(d time.Duration)` sets each attempt's timeout. `d` must be positive.
- `(*Scanner).Scan(ctx, hosts, ports) (<-chan Result, error)` validates input, resolves DNS names, and starts asynchronous scanning.

A `Scanner` is immutable after construction and safe to reuse for sequential or concurrent scans. Each scan has its own workers and result channel. The concurrency limit applies independently to each scan.

`Scan` returns validation and DNS resolution errors synchronously. If any host cannot be resolved, the scan is not started. Once scanning starts, individual connection failures are reported through `Result`, not as a second return error.

### Hosts

- `NewHost(raw string)` creates one target.
- `NewHosts(raw ...string)` creates a target list.

Whitespace around input is trimmed. Empty hosts and empty host lists are rejected. IP literals skip DNS resolution. Each DNS name is resolved to all its addresses, and every address is scanned. Repeated names (case-insensitive), equivalent IP literals, and repeated addresses returned for the same DNS name are deduplicated. Different names resolving to the same address remain separate targets so results retain the original host name.

### Ports

- `NewPorts(values ...int)` creates a list of individual ports.
- `NewRange(from, to int)` creates an inclusive range.
- `NewUnion(sets ...PortSet)` combines lists, ranges, and nested unions.

Valid ports are 1 through 65535. Port 0, negative values, values above 65535, reversed ranges, empty sets, and nil sets are rejected. Before scanning, ports are sorted and deduplicated; overlapping and adjacent ranges are merged.

### Results and states

`Result` contains the original `Host`, resolved `IP` (`netip.Addr`), `Port`, `State`, connection `Duration`, and the underlying `Err` for unsuccessful attempts.

| State | Meaning |
| --- | --- |
| `Open` | The TCP connection was established. |
| `Closed` | The connection was explicitly refused. |
| `Timeout` | The per-attempt timeout elapsed or the network operation timed out. |
| `Unreachable` | The host or network was unreachable. |
| `Canceled` | The scan context was canceled during the attempt. |
| `Error` | Another connection error occurred. |

States are derived from typed errors (`context` errors, `net.Error`, and network syscall errors), never by comparing error text. Successfully opened connections are closed immediately.

### Cancellation

Canceling the scan context stops scheduling new checks. Already running dials observe the same context and finish; their results are delivered before the result channel closes. Checks that never started do not produce results. As with other streaming Go APIs, the caller must keep reading the result channel after cancellation so workers can finish delivery.

## Development

Run the required test suite, including the race detector:

```sh
go test -race ./...
```

With Task installed, `task tests -- -race` runs the same suite and `task lint` runs `golangci-lint`.
