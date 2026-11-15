# tcpscan

A Go package for concurrent TCP Connect port scanning across one or more hosts (IPv4, IPv6, DNS).

## Features

- Concurrent TCP Connect scanning with a configurable connection limit.
- Configurable per-connection timeout and cancellation through `context.Context`.
- IPv4, IPv6, and DNS targets, including DNS names that resolve to multiple IP addresses.
- Individual ports, port ranges, and unions of both.
- Validation of hosts, ports, ranges, and scanner options.
- Duplicate host and port elimination.
- Structured results with the host, IP address, port, state, duration, and error.
- `open`, `closed`, `timeout`, `unreachable`, `canceled`, and `error` port states.
- Production code depends only on the Go standard library.

## Installation

```sh
go get github.com/uniqelus/tcpscan
```

The package requires Go 1.25.5 or later.

Testify is used only for test assertions and generated test doubles, which keep DNS and connection tests deterministic without real network access. Mockery generates those test doubles from the package interfaces. Neither tool is used by the production code.

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
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	source, err := tcpscan.NewTargetSource(
		tcpscan.NewHosts(
			"192.168.1.10",
			"2001:db8::10",
			"example.com",
		),
		tcpscan.NewPortUnion(
			tcpscan.NewPortList(22, 80, 443),
			tcpscan.NewPortRange(8000, 8010),
		),
	)
	if err != nil {
		log.Fatal(err)
	}

	scanner, err := tcpscan.NewScanner(
		tcpscan.WithConcurrency(100),
		tcpscan.WithConnectTimeout(500*time.Millisecond),
	)
	if err != nil {
		log.Fatal(err)
	}

	results := scanner.Scan(ctx, source.Targets(ctx))
	for result := range results {
		fmt.Println(result.String())
	}
}
```

`NewTargetSource` combines a `HostSet` with a `PortSet`. Use `NewPortList` for individual ports, `NewPortRange` for an inclusive range, and `NewPortUnion` to combine several sets. Invalid or empty port sets are rejected during construction. Duplicate and overlapping ports are scanned only once.

`Targets` resolves hosts and returns a stream of targets. Each IP address returned for a DNS name is scanned. Duplicate targets are eliminated; different names that resolve to the same IP address share a connection attempt but produce separate results. A host that cannot be resolved produces a single host-level result with `State == tcpscan.Error`, `Err == tcpscan.ErrInvalidAddr`, an invalid IP, and port `0`.

`NewScanner` accepts optional scanner settings. The defaults are 10 concurrent connections and a 500 ms connection timeout. `WithHostResolver` and `WithDialer` allow custom host resolution and connection implementations to be supplied to the target source and scanner respectively.

`Scan` starts the configured number of workers and returns a receive-only result channel. The channel is closed after all workers finish. Cancelling the context stops target delivery and active connection attempts; callers should continue reading the result channel until it is closed.

Each `Result` contains `Host`, `IP`, `Port`, `State`, `Duration`, and `Err`. An empty host set, an empty host, a port outside `1-65535`, a reversed range, and invalid options are returned as construction errors. The exported sentinel errors can be inspected with `errors.Is`.
