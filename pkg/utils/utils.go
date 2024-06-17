package utils

import (
	"bytes"
	"os"
	"os/exec"
)

func IsWindowsAdmin() bool {
	_, err := os.Open("\\\\.\\PHYSICALDRIVE0")
	if err != nil {
		return false
	}
	return true
}

func RunCmdWithEnv(c *exec.Cmd, env []string, arg ...string) ([]byte, []byte, error) {
	var stdout, stderr bytes.Buffer
	if len(env) > 0 {
		c.Env = os.Environ()
		c.Env = append(c.Env, env...)
	}

	if c.Stdout == nil {
		c.Stdout = &stdout
	}
	if c.Stderr == nil {
		c.Stderr = &stderr
	}

	err := c.Run()
	return stdout.Bytes(), stderr.Bytes(), err
}

func RunCmd(c *exec.Cmd, arg ...string) ([]byte, []byte, error) {
	var stdout, stderr bytes.Buffer
	if c.Stdout == nil {
		c.Stdout = &stdout
	}
	if c.Stderr == nil {
		c.Stderr = &stderr
	}

	err := c.Run()
	return stdout.Bytes(), stderr.Bytes(), err
}
