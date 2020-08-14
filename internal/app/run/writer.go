package run

import (
	"sync"

	"github.com/rs/zerolog/log"

	"github.com/hakluke/haksecuritytxt/internal/pkg/discloseio"
	"github.com/hakluke/haksecuritytxt/pkg/securitytxt"
)

type Writer struct {
	*Config

	inCh <-chan *securitytxt.SecurityTxt

	wg sync.WaitGroup
}

func NewWriter(config *Config, inCh <-chan *securitytxt.SecurityTxt) (*Writer, error) {
	w := &Writer{
		Config: config,
		inCh: inCh,
	}

	return w, nil
}

func (w *Writer) Start(errCh chan<- error) error {
	w.wg.Add(1)

	go func() {
		defer w.wg.Done()

		for txt := range(w.inCh) {
			fields := discloseio.FromSecurityTxt(txt)
			log.Info().Interface("disclose_io", fields).Msg("security.txt")

			if txt.ParseErrors() != nil {
				for _, err := range(txt.ParseErrors()) {
					log.Info().Str("domain", txt.Domain).Err(err).Msg("security.txt validation error")
				}
			}
		}
	}()

	return nil
}

func (w *Writer) Wait() {
	w.wg.Wait()
}
