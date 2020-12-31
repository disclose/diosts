package run

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/rs/zerolog/log"

	"github.com/disclose/diosts/internal/pkg/discloseio"
	"github.com/disclose/diosts/pkg/securitytxt"
)

type Writer struct {
	*Config
	version string

	inCh <-chan *securitytxt.SecurityTxt

	wg sync.WaitGroup
}

func NewWriter(version string, config *Config, inCh <-chan *securitytxt.SecurityTxt) (*Writer, error) {
	w := &Writer{
		Config: config,
		version: version,
		inCh: inCh,
	}

	return w, nil
}

func (w *Writer) Start(errCh chan<- error) error {
	w.wg.Add(1)

	go func() {
		defer w.wg.Done()

		// Start of list
		fmt.Printf("[\n")

		count := 0
		for txt := range(w.inCh) {
			if err := txt.Validate(); err != nil {
				log.Info().Str("domain", txt.Domain).Err(err).Msg("invalid security.txt")
				continue
			}

			log.Info().Str("domain", txt.Domain).Msg("security.txt found")

			if txt.ParseErrors() != nil {
				for _, err := range(txt.ParseErrors()) {
					log.Info().Str("domain", txt.Domain).Err(err).Msg("security.txt validation error")
				}
			}

			fields := discloseio.FromSecurityTxt(w.version, txt)
			out, err := json.MarshalIndent(fields, "  ", "  ")
			if err != nil {
				log.Warn().Err(err).Msg("error encoding json")
				continue
			}

			if count > 0 {
				fmt.Printf(",\n")
			}
			fmt.Printf("  %s", string(out))

			count++
		}

		// End of list
		fmt.Printf("\n]\n")
	}()

	return nil
}

func (w *Writer) Wait() {
	w.wg.Wait()
}
