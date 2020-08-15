package run

import (
	"sync"

	"github.com/disclose/securitytxt-scraper/pkg/securitytxt"
)

type WorkerPool struct {
	*Config

	client *securitytxt.DomainClient

	inCh <-chan string
	outCh chan<- *securitytxt.SecurityTxt

	wg sync.WaitGroup
}

func NewWorkerPool(config *Config, client *securitytxt.DomainClient, inCh <-chan string, outCh chan<- *securitytxt.SecurityTxt) (*WorkerPool, error) {
	w := &WorkerPool{
		Config: config,
		client: client,
		inCh: inCh,
		outCh: outCh,
	}

	return w, nil
}

func (w *WorkerPool) Run(errCh chan<- error) error {
	for i := 0; i < w.NumThreads; i++ {
		w.wg.Add(1)
		go w.work(errCh)
	}

	w.wg.Wait()

	// All workers done
	close(w.outCh)

	return nil
}

func (w *WorkerPool) work(errCh chan<- error) {
	defer w.wg.Done()

	for in := range(w.inCh) {
		txt, err := w.client.GetSecurityTxt(in)
		if err != nil {
			errCh <- err
			return
		}

		if txt != nil {
			w.outCh <- txt
		}
	}
}
