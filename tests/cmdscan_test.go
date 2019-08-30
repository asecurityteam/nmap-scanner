// +build integration

package tests

import (
	"bytes"
	"context"
	"io/ioutil"
	"testing"

	"github.com/asecurityteam/nmap-scanner/pkg/scanner"
	"github.com/stretchr/testify/require"
)

func TestExecCmd(t *testing.T) {
	ctx := context.Background()

	c := &scanner.ExecMaker{}
	r := c.MakeCommand(ctx, "ls", "-a", "-l")
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	err := r.RunCommand(&stdout, &stderr)
	require.Nil(t, err)

	out, _ := ioutil.ReadAll(&stdout)
	errOut, _ := ioutil.ReadAll(&stderr)
	require.NotEmpty(t, out)
	require.Empty(t, errOut)
}
