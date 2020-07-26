package run

import (
	"github.com/rs/zerolog/log"

	"github.com/hakluke/haksecuritytxt/internal/pkg/discloseio"
	"github.com/hakluke/haksecuritytxt/pkg/securitytxt"
)

type Writer struct {
	*Config

	inCh <-chan *securitytxt.SecurityTxt
}

func NewWriter(config *Config, inCh <-chan *securitytxt.SecurityTxt) (*Writer, error) {
	w := &Writer{
		Config: config,
		inCh: inCh,
	}

	return w, nil
}

func (w *Writer) Start(errCh chan<- error) error {
	go func() {
		for txt := range(w.inCh) {
			fields := discloseio.FromSecurityTxt(txt)
			log.Info().Interface("disclose_io", fields).Msg("security.txt")
		}
	}()

	return nil
}
