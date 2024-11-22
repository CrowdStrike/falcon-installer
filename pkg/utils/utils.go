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

	err := filepath.Walk(dir, func(path string, file os.FileInfo, err error) error {
		if err != nil {
			if !os.IsPermission(err) {
				return err
			}
		}

		if !file.IsDir() {
			f, err := regexp.MatchString(regex, file.Name())
			if err != nil {
				return err
			}
			if f {
				found = path
				return filepath.SkipDir // Stop searching once the file is found
			}
		}

		return nil
	})
	if err != nil {
		return "", err
	}

	if found == "" {
		return "", fmt.Errorf("Unable to find files in '%s' with regex: %s", dir, regex)
	}

	return found, nil
}

// RunCmdWithEnv runs a command with the specified environment variables.
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

// RunCmd runs a command.
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

// OpenFileForWriting opens a file for writing, creating the directory if it doesn't exist.
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
