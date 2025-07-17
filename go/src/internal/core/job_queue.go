package core

// JobQueue is a struct for managing a queue of jobs.
type JobQueue struct {
	// A channel to receive jobs.
	jobs chan *Job
}

// NewJobQueue creates a new JobQueue.
func NewJobQueue() *JobQueue {
	return &JobQueue{
		jobs: make(chan *Job, 100),
	}
}

// Add adds a job to the queue.
func (q *JobQueue) Add(job *Job) {
	q.jobs <- job
}

// Get gets a job from the queue.
func (q *JobQueue) Get() *Job {
	return <-q.jobs
}
