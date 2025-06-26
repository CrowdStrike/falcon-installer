// MIT License
//
// Copyright (c) 2024 CrowdStrike
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package utils

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// BoolToInt converts a boolean to an integer.
func BoolToInt(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}

// FindFile searches for a file in a directory that matches a regular expression.
func FindFile(dir string, regex string) (string, error) {
	found := ""

	re, err := regexp.Compile(regex)
	if err != nil {
		return "", fmt.Errorf("invalid regex: %w", err)
	}

	err = filepath.Walk(dir, func(path string, file os.FileInfo, err error) error {
		if err != nil {
			if os.IsPermission(err) {
				return nil // Skip directories we can't access
			}
			return err
		}

		if !file.IsDir() && re.MatchString(file.Name()) {
			found = path
			return filepath.SkipDir // Stop searching once the file is found
		}

		return nil
	})

	if err != nil {
		return "", err
	}

	if found == "" {
		return "", fmt.Errorf("no files found in '%s' matching regex: %s", dir, regex)
	}

	return found, nil
}

// CmdOption defines a functional option for command execution.
type CmdOption func(*exec.Cmd)

// WithEnv adds environment variables to the command.
func WithCmdEnvOption(env []string) CmdOption {
	return func(cmd *exec.Cmd) {
		cmd.Env = append(os.Environ(), env...)
	}
}

// WithStdin sets the standard input for the command.
func WithCmdStdinOption(stdin io.Reader) CmdOption {
	return func(cmd *exec.Cmd) {
		cmd.Stdin = stdin
	}
}

// RunCmd runs a command with optional configuration.
// It executes the specified command with given arguments and returns
// the stdout and stderr output as byte slices, along with any error encountered.
// The command's behavior can be customized using optional CmdOption parameters.
func RunCmd(cmnd string, args []string, opts ...CmdOption) ([]byte, []byte, error) {
	var stdout, stderr bytes.Buffer
	cmd := exec.Command(cmnd, args...)

	// Set default values
	cmd.Env = os.Environ() // Default to current environment
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Apply options
	for _, opt := range opts {
		opt(cmd)
	}

	err := cmd.Run()
	return stdout.Bytes(), stderr.Bytes(), err
}

// OpenFileForWriting opens a file for writing, creating the directory if it doesn't exist.
func OpenFileForWriting(dir, filename string) (*os.File, error) {
	if strings.Contains(filename, "/") {
		return nil, fmt.Errorf("refusing to download: '%s' includes '/' character", filename)
	}

	path := filepath.Join(dir, filename)
	safeLocation := filepath.Clean(path)

	if strings.Contains(safeLocation, "..") {
		return nil, fmt.Errorf("refusing to download: path '%s' looks suspicious", safeLocation)
	}

	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create directory: %w", err)
	}

	return os.OpenFile(safeLocation, os.O_CREATE|os.O_WRONLY, 0600)
}
