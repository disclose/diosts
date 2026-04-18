package run

import (
	"bufio"
	"os"
	"strings"
)

type Reader struct {
	*Config

	outCh chan<- string
}

func NewReader(config *Config, outCh chan<- string) (*Reader, error) {
	r := &Reader{
		Config: config,
		outCh:  outCh,
	}

	return r, nil
}

func (r *Reader) Start(errCh chan<- error) error {
	go func() {
		s := bufio.NewScanner(os.Stdin)
		for s.Scan() {
			domain := strings.TrimSpace(s.Text())
			if domain == "" {
				continue
			}
			r.outCh <- domain
		}

		if err := s.Err(); err != nil {
			errCh <- err
		}

		// All done, close channel
		close(r.outCh)
	}()

	return nil
}
