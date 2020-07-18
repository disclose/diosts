package run

import (
	"bufio"
	"fmt"
	"io"

	"github.com/rs/zerolog/log"
)

var schemas = []string{
	"http",
	"https",
}

var locations = []string{
	".well-known/security.txt",
	"security.txt",
}

func readDomains(in io.Reader, out chan string) {
	s := bufio.NewScanner(in)
	for s.Scan() {
		for _, schema := range(schemas) {
			for _, location := range(locations) {
				url := fmt.Sprintf("%s://%s/%s", schema, s.Text(), location)
				out <- url
			}
		}
	}

	if err := s.Err(); err != nil {
		log.Error().Err(err).Msg("error reading from stdin")
	}

	// All done, close channel
	close(out)
}
