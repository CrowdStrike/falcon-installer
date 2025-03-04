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

package falconctl

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
)

func TestGetCliPath(t *testing.T) {
	tests := []struct {
		name     string
		osType   string
		expected string
	}{
		{
			name:     "Linux path",
			osType:   "linux",
			expected: "/opt/CrowdStrike/falconctl",
		},
		{
			name:     "macOS path with darwin",
			osType:   "darwin",
			expected: "/Applications/Falcon.app/Contents/Resources/falconctl",
		},
		{
			name:     "macOS path with macos",
			osType:   "macos",
			expected: "/Applications/Falcon.app/Contents/Resources/falconctl",
		},
		{
			name:     "Windows path",
			osType:   "windows",
			expected: "C:\\Program Files\\CrowdStrike\\CSSensorSettings.exe",
		},
		{
			name:     "Unknown OS defaults to Linux path",
			osType:   "freebsd",
			expected: "/opt/CrowdStrike/falconctl",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Since getCliPath is not exported, we test through NewSensorConfig
			config := NewSensorConfig(tc.osType)

			// Use reflection to access the private path field
			configValue := reflect.ValueOf(config).Elem()
			pathField := configValue.FieldByName("path")

			if pathField.String() != tc.expected {
				t.Errorf("Expected path %q, got %q", tc.expected, pathField.String())
			}
		})
	}
}

func TestWithSensorMaintenanceTokenOption(t *testing.T) {
	// Create options struct
	opts := &sensorOptions{}

	// Test with empty token
	token := ""
	option := WithSensorMaintenanceTokenOption(token)
	option(opts)

	if opts.maintenanceToken == nil {
		t.Fatal("Expected maintenanceToken to be non-nil")
	}

	if *opts.maintenanceToken != "" {
		t.Errorf("Expected empty token, got %q", *opts.maintenanceToken)
	}

	// Test with non-empty token
	token = "test-token-123"
	option = WithSensorMaintenanceTokenOption(token)
	option(opts)

	if opts.maintenanceToken == nil {
		t.Fatal("Expected maintenanceToken to be non-nil")
	}

	if *opts.maintenanceToken != "test-token-123" {
		t.Errorf("Expected token %q, got %q", "test-token-123", *opts.maintenanceToken)
	}
}

func TestValidatePath(t *testing.T) {
	var mockExecPath string
	sensorConfigWithPath := func(path string) *SensorConfig {
		return &SensorConfig{
			path: path,
		}
	}

	// Create a temporary directory for our tests
	tempDir, err := os.MkdirTemp("", "falconctl-test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create a mock executable
	switch runtime.GOOS {
	case "windows":
		mockExecPath = filepath.Join(tempDir, "mock-falconctl.bat")

		// Batch file equivalent
		batchScript := "@echo off\necho mock"

		err = os.WriteFile(mockExecPath, []byte(batchScript), 0755) //nolint:gosec
		if err != nil {
			t.Fatalf("Failed to create mock batch file: %v", err)
		}
	default:
		mockExecPath = filepath.Join(tempDir, "mock-falconctl")

		// Create the mock executable file
		err = os.WriteFile(mockExecPath, []byte("#!/bin/sh\necho 'mock'"), 0755) //nolint:gosec
		if err != nil {
			t.Fatalf("Failed to create mock executable: %v", err)
		}
	}

	// Add temp dir to PATH
	oldPath := os.Getenv("PATH")
	os.Setenv("PATH", tempDir+string(os.PathListSeparator)+oldPath)
	defer os.Setenv("PATH", oldPath)

	// Test cases
	tests := []struct {
		name        string
		execPath    string
		expectError bool
	}{
		{
			name:        "Valid executable path",
			execPath:    mockExecPath,
			expectError: false,
		},
		{
			name:        "Invalid executable path",
			execPath:    filepath.Join(tempDir, "nonexistent"),
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Create a SensorConfig with the test path using the helper
			config := sensorConfigWithPath(tc.execPath)

			// Call Get which will indirectly call validatePath
			_, err := config.Get([]string{"-h"})

			if tc.expectError && err == nil {
				t.Errorf("Expected error but got none")
			}
			if !tc.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
		})
	}
}

func TestSet(t *testing.T) {
	// Create config with the expected path
	sensorConfigWithPath := func(path string) *SensorConfig {
		return &SensorConfig{
			path: path,
		}
	}

	// Create a temporary directory for our tests
	tempDir, err := os.MkdirTemp("", "falconctl-test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create mock executables for different platforms
	mockExecs := map[string]string{
		"linux":   filepath.Join(tempDir, "falconctl-linux"),
		"darwin":  filepath.Join(tempDir, "falconctl-darwin"),
		"windows": filepath.Join(tempDir, "falconctl-windows"),
	}

	// Create the mock executables with different behaviors
	for osType, path := range mockExecs {
		var scriptContent string
		switch runtime.GOOS {
		case "windows":
			switch osType {
			case "windows":
				// Windows mock (still a shell script for testing)
				scriptContent = `@echo off
echo Args: %*
echo Windows configuration updated 1>&2
exit /b 0
`
			default:
				scriptContent = `@echo off
echo Args: %*
echo Configuration updated 1>&2
exit /b 0
`
			}

		default:
			switch osType {
			case "linux":
				// Linux mock that echoes args and succeeds
				scriptContent = `#!/bin/sh
	echo "Args: $@"
	echo "CID set successfully" >&2
	exit 0
	`
			case "darwin":
				// macOS mock that reads from stdin and echoes it
				scriptContent = `#!/bin/sh
	echo "Args: $@"
	if [ "$1" = "--maintenance-token" ]; then
		token=$(cat)
		echo "Received token: $token" >&2
	fi
	echo "Configuration updated" >&2
	exit 0
	`
			case "windows":
				// Windows mock (still a shell script for testing)
				scriptContent = `#!/bin/sh
	echo "Args: $@"
	echo "Windows configuration updated" >&2
	exit 0
	`
			}
		}

		if runtime.GOOS == "windows" {
			path += ".bat"
		}

		err := os.WriteFile(path, []byte(scriptContent), 0755) //nolint:gosec
		if err != nil {
			t.Fatalf("Failed to create mock executable for %s: %v", osType, err)
		}
	}

	// Add temp dir to PATH
	oldPath := os.Getenv("PATH")
	os.Setenv("PATH", tempDir+string(os.PathListSeparator)+oldPath)
	defer os.Setenv("PATH", oldPath)

	// Test cases
	tests := []struct {
		name           string
		osType         string
		args           []string
		options        []SensorOption
		expectError    bool
		expectedOutput string // Output to check for in stderr
	}{
		{
			name:           "Basic set command on Linux",
			osType:         mockExecs["linux"],
			args:           []string{"--set-cid", "1234567890ABCDEF"},
			options:        nil,
			expectError:    false,
			expectedOutput: "CID set successfully",
		},
		{
			name:           "Set with maintenance token on macOS",
			osType:         mockExecs["darwin"],
			args:           []string{"--maintenance-token"},
			options:        []SensorOption{WithSensorMaintenanceTokenOption("test-token")},
			expectError:    false,
			expectedOutput: "Received token: test-token",
		},
		{
			name:           "Windows configuration",
			osType:         mockExecs["windows"],
			args:           []string{"/set", "CID=1234567890ABCDEF"},
			options:        nil,
			expectError:    false,
			expectedOutput: "Windows configuration updated",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Create config for this OS type
			config := sensorConfigWithPath(tc.osType)

			// Call Set
			err := config.Set(tc.args, tc.options...)

			// Check error
			if tc.expectError && err == nil {
				t.Errorf("Expected error but got none")
			}
			if !tc.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

		})
	}
}
