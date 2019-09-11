package scanner

import (
	"bytes"
	"context"
	"io"
	"os/exec"
	"strings"
	"sync"

	"github.com/asecurityteam/nmap-scanner/pkg/domain"
	"github.com/asecurityteam/nmap-scanner/pkg/logs"
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

// LoggingMaker wraps a CommandMaker in order to provide debug logging of
// shell commands.
type LoggingMaker struct {
	LogFn        domain.LogFn
	CommandMaker CommandMaker
}

// MakeCommand wraps the output of the nested maker with logging.
func (m *LoggingMaker) MakeCommand(ctx context.Context, cmd string, args ...string) CommandRunner {
	return &LoggingCmd{
		LogFn:         m.LogFn,
		Ctx:           ctx,
		CommandRunner: m.CommandMaker.MakeCommand(ctx, cmd, args...),
		Cmd:           cmd,
		Args:          args,
	}
}

// ExecMaker implements the CommandMaker using exec.Cmd.
type ExecMaker struct{}

// MakeCommand generates a CommandRunner implemented by ExecCmd.
func (*ExecMaker) MakeCommand(ctx context.Context, cmd string, args ...string) CommandRunner {
	return &ExecCmd{
		Cmd: exec.CommandContext(ctx, cmd, args...),
	}
}

// LoggingCmd emits debug logs when a command is issued.
type LoggingCmd struct {
	LogFn         domain.LogFn
	Ctx           context.Context
	CommandRunner CommandRunner
	Cmd           string
	Args          []string
}

// RunCommand captures the shell output.
func (c *LoggingCmd) RunCommand(stdout io.Writer, stderr io.Writer) error {
	var stdoutCopy bytes.Buffer
	var stderrCopy bytes.Buffer

	stdout = io.MultiWriter(&stdoutCopy, stdout)
	stderr = io.MultiWriter(&stderrCopy, stderr)
	err := c.CommandRunner.RunCommand(stdout, stderr)
	c.LogFn(c.Ctx).Debug(logs.CommandExecuted{
		Binary: c.Cmd,
		Args:   strings.Join(c.Args, " "),
		Out:    stdoutCopy.String(),
		Err:    stderrCopy.String(),
	})
	return err
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
