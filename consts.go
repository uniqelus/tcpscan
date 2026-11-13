package tcpscan

const (
	MinPort port = 1
	MaxPort port = 65535
)

type PortState string

const (
	Open        PortState = "open"
	Closed      PortState = "closed"
	Timeout     PortState = "timeout"
	Unreachable PortState = "unreachable"
	Canceled    PortState = "canceled"
	Error       PortState = "error"
)
