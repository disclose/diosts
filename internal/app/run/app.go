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

	"github.com/hakluke/haksecuritytxt/pkg/securitytxt"
)

type App struct {
	*Config

	pool *WorkerPool
}

func New(config *Config) (*App, error) {
	client, err := securitytxt.NewDomainClient(config.SecurityTxt)
	if err != nil {
		return nil, err
	}

	pool, err := NewWorkerPool(client, config.NumThreads)
	if err != nil {
		return nil, err
	}

	a := &App{
		Config: config,
		pool: pool,
	}

	return a, nil
}

func (a *App) Run() error {
	// TODO
	// - Add counter: total input. total securitytxt, total valid
	// - validate input
	// - error output for non-existent domain etc

	// Read domains from stdin
	go readDomains(os.Stdin, a.pool.WorkCh)

	// Output
	// TBD

	return a.pool.Run()
}
