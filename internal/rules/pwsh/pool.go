package pwsh

import "runtime"

// defaultPoolSize is the number of pwsh workers to keep ready.
// Capped at 4: each worker is a full pwsh subprocess (~50 MB RSS + JIT warm-up).
const defaultPoolSize = 4

// WorkerPool holds a fixed set of pwsh Worker subprocesses.
// Callers acquire a worker for the duration of one Parse() call and return it
// immediately after, allowing N concurrent parses with N workers.
type WorkerPool struct {
	workers chan *Worker
}

// NewWorkerPool creates a pool of size workers, all pointing to pwshPath.
// size <= 0 uses min(GOMAXPROCS, defaultPoolSize).
func NewWorkerPool(pwshPath string, size int) (*WorkerPool, error) {
	if size <= 0 {
		size = min(runtime.GOMAXPROCS(0), defaultPoolSize)
	}
	ch := make(chan *Worker, size)
	for range size {
		w, err := NewWorker(pwshPath)
		if err != nil {
			close(ch)
			for w := range ch {
				w.Stop()
			}
			return nil, err
		}
		ch <- w
	}
	return &WorkerPool{workers: ch}, nil
}

// Parse acquires an idle worker, delegates the parse, then returns the worker.
// Blocks if all workers are busy. Safe for concurrent use.
func (p *WorkerPool) Parse(cmd string) (Response, error) {
	w := <-p.workers
	defer func() { p.workers <- w }()
	return w.Parse(cmd)
}

// Stop waits for all in-flight Parse calls to complete, then shuts down every
// worker. Must not be called concurrently with itself.
func (p *WorkerPool) Stop() {
	for range cap(p.workers) {
		w := <-p.workers
		w.Stop()
	}
}
