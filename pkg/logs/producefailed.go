package logs

// ProduceFailed indicates we were unable to report results of a scan.
type ProduceFailed struct {
	Message    string `logevent:"message,default=produce-failed"`
	TargetHost string `logevent:"target_host"`
	Reason     string `logevent:"reason"`
}
