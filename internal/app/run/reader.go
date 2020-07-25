package run

import (
	"bufio"
	"io"
)

func readDomains(in io.Reader, out chan string) {
	s := bufio.NewScanner(in)
	for s.Scan() {
		out <- url
	}

	// All done, close channel
	close(out)
}
