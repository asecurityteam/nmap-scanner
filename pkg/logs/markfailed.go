package logs

// MarkFailed indicates we were unable to set the in-progress marker.
type MarkFailed struct {
	Message string `logevent:"message,default=mark-failed"`
	Reason  string `logevent:"reason"`
}
