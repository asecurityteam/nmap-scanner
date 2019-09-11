package logs

// CommandExecuted details a shell command.
type CommandExecuted struct {
	Message string `logevent:"message,default=command-executed"`
	Binary  string `logevent:"binary"`
	Args    string `logevent:"args"`
	Out     string `logevent:"out"`
	Err     string `logevent:"err"`
}
