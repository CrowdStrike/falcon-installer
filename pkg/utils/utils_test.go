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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func testCmnd() (string, []string, string) {
	//case statement to return command for testing on windows and linux
	switch runtime.GOOS {
	case "windows":
		cmd := "cmd.exe"
		args := []string{"/c", "echo", "hello", "world"}
		newline := "\r\n"
		return cmd, args, newline
	default:
		cmd := "echo"
		args := []string{"hello", "world"}
		newline := "\n"
		return cmd, args, newline
	}
}

func TestBoolToInt(t *testing.T) {
	if BoolToInt(true) != 1 {
		t.Errorf("Expected input: %v, got: %v", 1, BoolToInt(true))
	}
	if BoolToInt(false) != 0 {
		t.Errorf("Expected input: %v, got: %v", 0, BoolToInt(false))
	}
}

func TestFindFile(t *testing.T) {
	switch runtime.GOOS {
	case "windows":
		file, err := FindFile("C:\\testingFakeDIr", "")
		if err == nil {
			t.Errorf("Expected error: %v, got: %v", err, file)
		}

		file, err = FindFile("C:\\Windows", "\\")
		if err == nil {
			t.Errorf("Expected error: %v, got: %v", err, file)
		}

		file, err = FindFile("C:\\Windows\\System32\\Sysprep", "not[goingtofindthis]file")
		if err == nil {
			t.Errorf("Expected error: %v, got: %v", err, file)
		}

		file, err = FindFile("C:\\Windows\\System32\\Sysprep", "sys.*exe")
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}

		if !strings.Contains(file, "sysprep.exe") {
			t.Errorf("Expected input: %q, got: %q", "sysprep.exe", file)
		}

	default:
		file, err := FindFile("/testingFakeDIr", "")
		if err == nil {
			t.Errorf("Expected error: %v, got: %v", err, file)
		}

		file, err = FindFile("/etc", "\\")
		if err == nil {
			t.Errorf("Expected error: %v, got: %v", err, file)
		}

		file, err = FindFile("/etc/", "not[goingtofindthis]file")
		if err == nil {
			t.Errorf("Expected error: %v, got: %v", err, file)
		}

		file, err = FindFile("/etc/", "h[o]+sts")
		if err != nil {
			t.Errorf("Expected error: %v, got: %v", err, file)
		}

		if !strings.Contains(file, "hosts") {
			t.Errorf("Expected input: %q, got: %q", "hosts", file)
		}

	}
}

func TestRunCmdWithEnv(t *testing.T) {
	cmd, args, newline := testCmnd()
	env := "FOO=bar"
	expectedOutput := fmt.Sprintf("hello world%s", newline)

	stdout, stderr, err := RunCmd(cmd, args, WithCmdEnvOption([]string{env}))
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if string(stdout) != expectedOutput {
		t.Errorf("Expected input: %q, got: %q", expectedOutput, string(stdout))
	}
	if string(stderr) != "" {
		t.Errorf("Expected output: %q, got: %q", "", string(stderr))
	}
}

func TestRunCmd(t *testing.T) {
	cmd, args, newline := testCmnd()
	expectedOutput := fmt.Sprintf("hello world%s", newline)

	stdout, stderr, err := RunCmd(cmd, args)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if string(stdout) != expectedOutput {
		t.Errorf("Expected input: %q, got: %q", expectedOutput, string(stdout))
	}
	if string(stderr) != "" {
		t.Errorf("Expected output: %q, got: %q", "", string(stderr))
	}
}

func TestRunCmdWithStdin(t *testing.T) {
	cmd, args, newline := testCmnd()
	stdin := "well..."
	expectedOutput := fmt.Sprintf("hello world%s", newline)

	stdout, stderr, err := RunCmd(cmd, args, WithCmdStdinOption(strings.NewReader(stdin)))
	if err != nil {
		if !strings.Contains(err.Error(), "could not write to stdin") {
			t.Errorf("Unexpected error: %v", err)
		}
	}

	if string(stdout) != expectedOutput {
		t.Errorf("Expected input: %q, got: %q", expectedOutput, string(stdout))
	}
	if string(stderr) != "" {
		t.Errorf("Expected output: %q, got: %q", "", string(stderr))
	}
}

func TestOpenFileForWriting(t *testing.T) {
	filename := "test.txt"
	dir := os.TempDir()

	file, err := OpenFileForWriting(dir, filename)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	file.Close()

	// cleanup
	if err := os.Remove(file.Name()); err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	filename = "/test.txt"
	_, err = OpenFileForWriting(dir, filename)
	if !strings.Contains(err.Error(), "refusing to download: '/test.txt' includes '/' character") {
		t.Errorf("Unexpected error: %v", err)
	}

	filename = "..test.txt"
	_, err = OpenFileForWriting(dir, filename)
	if !strings.Contains(err.Error(), "looks suspicious") {
		t.Errorf("Unexpected error: %v", err)
	}
}

// TestOpenFileForWritingReplacesExistingFile verifies a leftover regular file from a prior run is
// removed and replaced cleanly.
func TestOpenFileForWritingReplacesExistingFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	filename := "dummyfile.bin"
	existing := filepath.Join(dir, filename)

	if err := os.WriteFile(existing, []byte("stale contents"), 0600); err != nil {
		t.Fatalf("failed to seed existing file: %v", err)
	}

	file, err := OpenFileForWriting(dir, filename)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	defer file.Close()

	if got := filepath.Clean(file.Name()); got != filepath.Clean(existing) {
		t.Errorf("expected file at %s, got %s", existing, got)
	}

	// The file must be freshly created (empty), not the stale contents.
	info, err := file.Stat()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if info.Size() != 0 {
		t.Errorf("expected freshly created empty file, got size %d", info.Size())
	}
}

// TestOpenFileForWritingDoesNotFollowSymlink verifies a symlink planted at the destination
// filename is removed rather than followed, leaving the symlink's target untouched.
func TestOpenFileForWritingDoesNotFollowSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on Windows")
	}
	t.Parallel()

	dir := t.TempDir()

	// A file outside the download directory that a planted symlink could otherwise redirect writes to.
	external := filepath.Join(t.TempDir(), "external.txt")
	externalContents := []byte("do not overwrite me")
	if err := os.WriteFile(external, externalContents, 0600); err != nil {
		t.Fatalf("failed to seed external file: %v", err)
	}

	// Plant a symlink at the destination filename pointing at the external file.
	filename := "dummyfile.bin"
	planted := filepath.Join(dir, filename)
	if err := os.Symlink(external, planted); err != nil {
		t.Fatalf("failed to plant symlink: %v", err)
	}

	file, err := OpenFileForWriting(dir, filename)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	defer file.Close()

	if _, err := file.Write([]byte("downloaded bytes")); err != nil {
		t.Fatalf("Unexpected error writing: %v", err)
	}

	// The external file must be untouched.
	got, err := os.ReadFile(external)
	if err != nil {
		t.Fatalf("Unexpected error reading external file: %v", err)
	}
	if string(got) != string(externalContents) {
		t.Errorf("external file was modified: got %q, want %q", got, externalContents)
	}

	// The destination must now be a regular file, not a symlink.
	info, err := os.Lstat(planted)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		t.Errorf("destination is still a symlink")
	}
}

// TestOpenFileForWritingResolvesSymlinkedDir verifies that when the directory itself is a symlink,
// the file is created under the target directory (the kernel traverses the dir symlink naturally).
func TestOpenFileForWritingResolvesSymlinkedDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on Windows")
	}
	t.Parallel()

	target := t.TempDir()
	link := filepath.Join(t.TempDir(), "falcon")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("failed to symlink dir: %v", err)
	}

	filename := "dummyfile.bin"
	file, err := OpenFileForWriting(link, filename)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	defer file.Close()

	// The file must be physically present under the target directory the link points to.
	if _, err := os.Stat(filepath.Join(target, filename)); err != nil {
		t.Errorf("file not found under target dir: %v", err)
	}
}

func TestVerifyFileHash(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "payload")
	contents := []byte("falcon sensor bytes")
	if err := os.WriteFile(path, contents, 0600); err != nil {
		t.Fatalf("failed to seed file: %v", err)
	}

	// SHA256 of "falcon sensor bytes".
	sum := sha256.Sum256(contents)
	correct := hex.EncodeToString(sum[:])

	tests := []struct {
		name     string
		path     string
		expected string
		wantErr  bool
	}{
		{name: "matching hash", path: path, expected: correct, wantErr: false},
		{name: "matching hash uppercase", path: path, expected: strings.ToUpper(correct), wantErr: false},
		{name: "mismatching hash", path: path, expected: "deadbeef", wantErr: true},
		{name: "missing file", path: filepath.Join(dir, "nope"), expected: correct, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := VerifyFileHash(tt.path, tt.expected)
			if tt.wantErr && err == nil {
				t.Errorf("expected an error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestRedactSecret(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		expected string
	}{
		{name: "non-empty value fully redacted", value: "supersecret", expected: "[REDACTED]"},
		{name: "short value fully redacted", value: "ab", expected: "[REDACTED]"},
		{name: "empty value stays empty", value: "", expected: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := RedactSecret(tt.value); got != tt.expected {
				t.Errorf("RedactSecret(%q) = %q, want %q", tt.value, got, tt.expected)
			}
		})
	}
}

func TestRedactArgs(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		expected []string
	}{
		{
			name:     "linux maintenance token value is redacted",
			args:     []string{"-s", "--maintenance-token=supersecret"},
			expected: []string{"-s", "--maintenance-token=[REDACTED]"},
		},
		{
			name:     "windows maintenance token value is redacted",
			args:     []string{"/silent", "/upgrade", "/maintenance_token=supersecret"},
			expected: []string{"/silent", "/upgrade", "/maintenance_token=[REDACTED]"},
		},
		{
			name:     "linux provisioning token value is redacted",
			args:     []string{"-s", "-f", "--provisioning-token=abcd12345"},
			expected: []string{"-s", "-f", "--provisioning-token=[REDACTED]"},
		},
		{
			name:     "windows provisioning token value is redacted",
			args:     []string{"ProvToken=abcd12345", "CID=xyz"},
			expected: []string{"ProvToken=[REDACTED]", "CID=xyz"},
		},
		{
			name:     "short token value is redacted",
			args:     []string{"--maintenance-token=ab"},
			expected: []string{"--maintenance-token=[REDACTED]"},
		},
		{
			name:     "no sensitive token leaves args unchanged",
			args:     []string{"-g", "--cid"},
			expected: []string{"-g", "--cid"},
		},
		{
			name:     "bare maintenance-token flag without value is kept",
			args:     []string{"--maintenance-token"},
			expected: []string{"--maintenance-token"},
		},
		{
			name:     "empty args",
			args:     []string{},
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := RedactArgs(tt.args)
			if !reflect.DeepEqual(got, tt.expected) {
				t.Errorf("RedactArgs(%v) = %v, want %v", tt.args, got, tt.expected)
			}
		})
	}
}
