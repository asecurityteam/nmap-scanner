package logs

// EnqueueFailed indicates we were unable to enqueue an async scan job.
type EnqueueFailed struct {
	Message    string `logevent:"message,default=enqueue-failed"`
	TargetHost string `logevent:"target_host"`
	Reason     string `logevent:"reason"`
}
