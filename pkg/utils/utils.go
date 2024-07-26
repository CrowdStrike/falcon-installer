package utils

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func RunCmdWithEnv(cmnd string, env string, arg []string) ([]byte, []byte, error) {
	var stdout, stderr bytes.Buffer
	c := exec.Command(cmnd, arg...)

	if len(env) > 0 {
		c.Env = os.Environ()
		c.Env = append(c.Env, env)
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

func RunCmd(cmnd string, arg []string) ([]byte, []byte, error) {
	var stdout, stderr bytes.Buffer
	c := exec.Command(cmnd, arg...)

	if c.Stdout == nil {
		c.Stdout = &stdout
	}
	if c.Stderr == nil {
		c.Stderr = &stderr
	}

	err := c.Run()
	return stdout.Bytes(), stderr.Bytes(), err
}

// OpenFileForWriting opens a file for writing, creating the directory if it doesn't exist
func OpenFileForWriting(dir, filename string) (*os.File, error) {
	if strings.Contains(filename, "/") {
		return nil, fmt.Errorf("Refusing to download: '%s' includes '/' character", filename)
	}
	path := filepath.Join(dir, filename)
	safeLocation := filepath.Clean(path)
	if strings.Contains(safeLocation, "..") {
		return nil, fmt.Errorf("Refusing to download: Path '%s' looks suspicious", safeLocation)
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	return os.OpenFile(safeLocation, os.O_CREATE|os.O_WRONLY, 0600)
}
