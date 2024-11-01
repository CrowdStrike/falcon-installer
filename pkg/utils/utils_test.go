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
