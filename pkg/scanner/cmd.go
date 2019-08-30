package scanner

import (
	"context"
	"io"
	"os/exec"
	"sync"
)

// CommandRunner is a stand-in for calling cmd.Run() while also capturing
// input.
type CommandRunner interface {
	RunCommand(stdout io.Writer, stderr io.Writer) error
}

// CommandMaker is a stand-in for creating and instance of exec.Cmd directly.
type CommandMaker interface {
	MakeCommand(ctx context.Context, cmd string, args ...string) CommandRunner
}

// ExecMaker implements the CommandMaker using exec.Cmd.
type ExecMaker struct{}

// MakeCommand generates a CommandRunner implemented by ExecCmd.
func (*ExecMaker) MakeCommand(ctx context.Context, cmd string, args ...string) CommandRunner {
	return &ExecCmd{
		Cmd: exec.CommandContext(ctx, cmd, args...),
	}
}

// ExecCmd implements CommandRunner using exec.Cmd.
type ExecCmd struct {
	Cmd  *exec.Cmd
	lock sync.Mutex
}

// RunCommand executes the bundled command and returns the results
func (c *ExecCmd) RunCommand(stdout io.Writer, stderr io.Writer) error {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.Cmd.Stdout = stdout
	c.Cmd.Stderr = stderr
	return c.Cmd.Run()
}
