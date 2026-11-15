package tcpscan

import "context"

type Scanner struct {
}

func NewScanner() *Scanner {
	return &Scanner{}
}

func (s *Scanner) Scan(ctx context.Context, targets <-chan Target) <-chan Result {
	return nil
}
