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
	"fmt"
	"os"
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

	stdout, stderr, err := RunCmdWithEnv(cmd, env, args)
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
	if !strings.Contains(err.Error(), "Refusing to download: '/test.txt' includes '/' character") {
		t.Errorf("Unexpected error: %v", err)
	}

	filename = "..test.txt"
	_, err = OpenFileForWriting(dir, filename)
	if !strings.Contains(err.Error(), "looks suspicious") {
		t.Errorf("Unexpected error: %v", err)
	}
}
