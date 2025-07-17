package core

// WorkerPool is a struct for managing a pool of workers.
type WorkerPool struct {
	// A channel to receive jobs.
	jobQueue chan *Job
	// A channel to quit the workers.
	quit chan bool
	// A list of workers.
	workers []*Worker
}

// NewWorkerPool creates a new WorkerPool.
func NewWorkerPool(jobQueue chan *Job) *WorkerPool {
	return &WorkerPool{
		jobQueue: jobQueue,
		quit:     make(chan bool),
	}
}

// Start starts the worker pool.
func (p *WorkerPool) Start() {
	// Create a number of workers.
	for i := 0; i < 10; i++ {
		// Create a new worker.
		worker := NewWorker(p.jobQueue, p.quit)
		// Add the worker to the list.
		p.workers = append(p.workers, worker)
		// Start the worker.
		worker.Start()
	}
}

// Stop stops the worker pool.
func (p *WorkerPool) Stop() {
	// Send a quit signal to all the workers.
	for i := 0; i < len(p.workers); i++ {
		p.quit <- true
	}
}
