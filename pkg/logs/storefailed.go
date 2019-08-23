package logs

// StoreFailed indicates we were unable to persist scan results for an
// async job.
type StoreFailed struct {
	Message    string `logevent:"message,default=store-failed"`
	Reason     string `logevent:"reason"`
	TargetHost string `logevent:"target_host"`
}
