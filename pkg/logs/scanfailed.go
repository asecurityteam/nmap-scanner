package logs

// ScanFailed indicates we were unable complete a scan.
type ScanFailed struct {
	Message    string `logevent:"message,default=scan-failed"`
	TargetHost string `logevent:"target_host"`
	Reason     string `logevent:"reason"`
}
