package run

import (
	"bufio"
	"crypto/tls"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

type App struct {
	*Config

	client *http.Client
	wg sync.WaitGroup
}

func New(config *Config) (*App, error) {
	dialer := net.Dialer{
		Timeout: 0,
		KeepAlive: 0,
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			Dial: dialer.Dial,
			TLSHandshakeTimeout: 5 * time.Second,
		},
	}

	a := &App{
		Config: config,
		client: client,
	}

	return a, nil
}

func (a *App) Run() error {
	endpointCh := make(chan string, 1)

	// TODO
	// - Add counter
	// - validate input
	// - error output for non-existent domain etc

	// Read domains from stdin
	go readDomains(os.Stdin, endpointCh)

	for i := 0; i < a.NumThreads; i++ {
		a.wg.Add(1)
		go a.scrape(endpointCh)
	}

	a.wg.Wait()

	return nil
}

var fields = []string{
	"Contact",
	"Encryption",
	"Acknowledgments",
	"Preferred-Languages",
	"Canonical",
	"Policy",
	"Hiring",
}

func (a *App) scrape(in <-chan string) {
	defer a.wg.Done()

	// TODO
	// - separate function for loop
	// - logger

	for url := range(in) {
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			log.Warn().Err(err).Str("url", url).Msg("failed to create request")
			continue
		}

		resp, err := a.client.Do(req)
		if err != nil {
			// Non-2xx codes are not errors
			log.Warn().Err(err).Str("url", url).Msg("request failed")
			continue
		}

		if resp.StatusCode != http.StatusOK {
			log.Debug().Int("status_code", resp.StatusCode).Str("url", url).Msg("unable to retrieve")
			continue
		}

		parsed := map[string]string{}

		body := bufio.NewScanner(resp.Body)
		for body.Scan() {
			t := body.Text()

			// Skip comments
			if t[0] == '#' {
				continue
			}

			fields := strings.Split(t, ": ")
			if len(fields) != 2 {
				log.Debug().Err(err).Str("url", url).Str("line", t).Msg("invalid line")
				continue
			}

			parsed[fields[0]] = fields[1]
		}
		resp.Body.Close()

		if err := body.Err(); err != nil {
			log.Warn().Err(err).Str("url", url).Msg("error reading body")
			continue
		}

		if len(parsed) == 0 {
			log.Debug().Str("url", url).Msg("no fields found")
			continue
		}

		// TODO: domain
		fieldLog := log.Info().Str("url", url)
		for k, v := range(parsed) {
			fieldLog = fieldLog.Str(k, v)
		}
		fieldLog.Msg("security.txt fields")
	}
}
