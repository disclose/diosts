package run

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"github.com/rs/zerolog/log"

	"github.com/disclose/diosts/internal/pkg/discloseio"
	"github.com/disclose/diosts/pkg/securitytxt"
)

type Writer struct {
	*Config
	version string

	inCh               <-chan *securitytxt.SecurityTxt
	nonCompliantOutput *os.File

	wg sync.WaitGroup
}

func NewWriter(version string, config *Config, inCh <-chan *securitytxt.SecurityTxt) (*Writer, error) {
	w := &Writer{
		Config:  config,
		version: version,
		inCh:    inCh,
	}

	// If non-compliant output file is specified, open it
	if config.NonCompliantOutputPath != "" {
		var err error
		w.nonCompliantOutput, err = os.Create(config.NonCompliantOutputPath)
		if err != nil {
			return nil, fmt.Errorf("failed to create non-compliant output file: %w", err)
		}
		// Write the beginning of the JSON array
		_, err = w.nonCompliantOutput.WriteString("[\n")
		if err != nil {
			return nil, fmt.Errorf("failed to write to non-compliant output file: %w", err)
		}
	}

	return w, nil
}

func (w *Writer) Start(errCh chan<- error) error {
	w.wg.Add(1)

	go func() {
		defer w.wg.Done()
		defer w.closeNonCompliantOutput()

		// Start of list
		fmt.Printf("[\n")

		count := 0
		nonCompliantCount := 0
		for txt := range w.inCh {
			// Always validate, but now we're tracking compliance status
			if err := txt.Validate(); err != nil {
				log.Info().Str("domain", txt.Domain).Err(err).Msg("invalid security.txt")
			}

			log.Info().Str("domain", txt.Domain).Msg("security.txt found")

			if txt.ParseErrors() != nil {
				for _, err := range txt.ParseErrors() {
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

			// If the security.txt is not RFC compliant and we have an output file, write to it
			if !txt.IsRFCCompliant && w.nonCompliantOutput != nil {
				if nonCompliantCount > 0 {
					_, err = w.nonCompliantOutput.WriteString(",\n")
					if err != nil {
						log.Warn().Err(err).Msg("error writing to non-compliant output file")
					}
				}
				_, err = w.nonCompliantOutput.WriteString("  " + string(out))
				if err != nil {
					log.Warn().Err(err).Msg("error writing to non-compliant output file")
				}
				nonCompliantCount++
			}
		}

		// End of list
		fmt.Printf("\n]\n")
	}()

	return nil
}

func (w *Writer) closeNonCompliantOutput() {
	if w.nonCompliantOutput != nil {
		// Write the end of the JSON array
		_, err := w.nonCompliantOutput.WriteString("\n]\n")
		if err != nil {
			log.Warn().Err(err).Msg("error finalizing non-compliant output file")
		}
		err = w.nonCompliantOutput.Close()
		if err != nil {
			log.Warn().Err(err).Msg("error closing non-compliant output file")
		}
	}
}

func (w *Writer) Wait() {
	w.wg.Wait()
}
