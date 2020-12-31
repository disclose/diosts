package run

import (
	"github.com/rs/zerolog/log"

	"github.com/disclose/diosts/pkg/securitytxt"
)

type App struct {
	*Config

	reader *Reader
	writer *Writer
	pool *WorkerPool
}

func New(version string, config *Config) (*App, error) {
	domainCh := make(chan string, config.NumThreads)
	txtCh := make(chan *securitytxt.SecurityTxt, config.NumThreads)

	reader, err := NewReader(config, domainCh)
	if err != nil {
		return nil, err
	}

	writer, err := NewWriter(version, config, txtCh)
	if err != nil {
		return nil, err
	}

	client, err := securitytxt.NewDomainClient(&config.SecurityTxt)
	if err != nil {
		return nil, err
	}

	pool, err := NewWorkerPool(config, client, domainCh, txtCh)
	if err != nil {
		return nil, err
	}

	a := &App{
		Config: config,
		reader: reader,
		writer: writer,
		pool: pool,
	}

	return a, nil
}

// We have five different outcomes when scraping a domain:
// - Success!; log info message, json output
// - No security.txt available; log info message
// - Error during scraping; log info message
// - Scraped, but invalid security.txt; log info message
// - Scraped, partly invalid security.txt; log info message, list of violations, json
// - Application error; log fatal message, quit

func (a *App) Run() error {
	errCh := make(chan error, 1)
	go func() {
		err := <-errCh
		if err != nil {
			log.Fatal().Err(err).Msg("")
		}
	}()

	// TODO
	// - Add counter: total input, total security.txt found, total valid, etc
	// - Validate field values
	// - Graceful shutdown
	// - Store redirects

	// Read domains - will close domainCh when done
	err := a.reader.Start(errCh)
	if err != nil {
		return err
	}

	// Write domains - will stop when txtCh is closed
	err = a.writer.Start(errCh)
	if err != nil {
		return err
	}

	// Will run until domainCh is closed and closes txtCh
	err = a.pool.Run(errCh)
	if err != nil {
		return err
	}

	// Wait until all security.txt results have been written
	a.writer.Wait()

	return nil
}
