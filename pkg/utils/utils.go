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
	"crypto/sha256"
	"encoding/hex"
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

	// Remove any pre-existing file or symlink at the destination filename
	if err := os.Remove(safeLocation); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to remove existing file %s: %w", safeLocation, err)
	}

	return os.OpenFile(safeLocation, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600)
}

// VerifyFileHash computes the SHA256 of the file at path and compares it to expected (a hex-encoded
// digest). The comparison is case-insensitive. It returns an error if the file cannot be read or if
// the computed digest does not match expected.
func VerifyFileHash(path, expected string) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open %s for verification: %w", path, err)
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return fmt.Errorf("failed to read %s for verification: %w", path, err)
	}

	actual := hex.EncodeToString(hash.Sum(nil))
	if !strings.EqualFold(actual, expected) {
		return fmt.Errorf("checksum mismatch for %s: expected %s, got %s", path, expected, actual)
	}

	return nil
}

// sensitiveArgPrefixes are the command-line argument forms whose value is a secret token. Linux
// falconctl uses "--<name>=VALUE"; the Windows installer uses "/maintenance_token=VALUE" and
// "ProvToken=VALUE".
var sensitiveArgPrefixes = []string{
	"--maintenance-token=",
	"/maintenance_token=",
	"--provisioning-token=",
	"ProvToken=",
}

// RedactSecret replaces a non-empty value with "[REDACTED]" so a secret can be safely logged. An
// empty value is returned unchanged so an unset field is not misreported as a secret.
func RedactSecret(value string) string {
	if value == "" {
		return ""
	}
	return "[REDACTED]"
}

// RedactArgs returns a copy of args with any sensitive token value replaced via RedactSecret so the
// arguments can be safely logged. Arguments that do not carry a token are returned unchanged.
func RedactArgs(args []string) []string {
	redacted := make([]string, len(args))
	for i, arg := range args {
		redacted[i] = arg
		for _, prefix := range sensitiveArgPrefixes {
			if strings.HasPrefix(arg, prefix) {
				redacted[i] = prefix + RedactSecret(arg[len(prefix):])
				break
			}
		}
	}
	return redacted
}
