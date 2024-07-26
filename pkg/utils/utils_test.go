package utils_test

import (
	"os"
	"strings"
	"testing"

	"github.com/crowdstrike/falcon-installer/pkg/utils"
)

func TestRunCmdWithEnv(t *testing.T) {
	cmd := "echo"
	env := "FOO=bar"
	args := []string{"hello", "world"}
	expectedOutput := "hello world\n"

	stdout, stderr, err := utils.RunCmdWithEnv(cmd, env, args)
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
	cmd := "echo"
	args := []string{"hello", "world"}
	expectedOutput := "hello world\n"

	stdout, stderr, err := utils.RunCmd(cmd, args)
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

	file, err := utils.OpenFileForWriting(dir, filename)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	defer file.Close()

	// cleanup
	if err := os.Remove(file.Name()); err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	filename = "/test.txt"
	_, err = utils.OpenFileForWriting(dir, filename)
	if !strings.Contains(err.Error(), "Refusing to download: '/test.txt' includes '/' character") {
		t.Errorf("Unexpected error: %v", err)
	}

	filename = "..test.txt"
	_, err = utils.OpenFileForWriting(dir, filename)
	if !strings.Contains(err.Error(), "looks suspicious") {
		t.Errorf("Unexpected error: %v", err)
	}
}
