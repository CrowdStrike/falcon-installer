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

//go:build windows
// +build windows

package osutils

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestWinFalconInstalled(t *testing.T) {
	got, err := FalconInstalled("windows")
	if err != nil {
		t.Errorf("Expected no error when checking for Falcon service, got: %v", err)
	}
	if got {
		t.Errorf("Expected Falcon Sensor not to be installed: Got: %v", got)
	}

	got, err = FalconInstalled("unknown")
	if err == nil {
		t.Errorf("Expected error: %v", err)
	}

	if got {
		t.Errorf("Expected Falcon Sensor not to be installed: Got: %v, Error: %v", got, err)
	}
}

func TestWinRunningWithPrivileges(t *testing.T) {
	got, err := RunningWithPrivileges("windows")
	if err != nil {
		if err.Error() != "you must run this program as an Administrator" {
			t.Error(err)
		}
	}

	if got {
		t.Log("Running on Windows as Administrator")
	} else {
		t.Log("Running on Windows as non-Administrator")
	}

	got, err = RunningWithPrivileges("unknown")
	if err == nil {
		t.Errorf("Expected error: %v", err)
	}

	if got {
		t.Errorf("Expected not to be running with privileges on an unsupported OS: Got: %v, Error: %v", got, err)
	}
}

func TestIsWindowsAdmin(t *testing.T) {
	if isWindowsAdmin() {
		t.Log("Running on Windows as Administrator")
	} else {
		t.Log("Running on Windows as non-Administrator")
	}
}

func TestReadEtcRelease(t *testing.T) {
	os, ver, err := ReadEtcRelease("windows")
	if err != nil {
		t.Error(err)
	}

	if os != "windows" || ver != "" {
		t.Errorf("Expected os=windows, and ver='': Got: os: %s, ver: %s", os, ver)
	}

	os, ver, err = ReadEtcRelease("unknown")
	if err == nil {
		t.Errorf("Expected error: %v", err)
	}

	if os != "" || ver != "" {
		t.Errorf("Expected empty string: Got: os: %s, ver: %s", os, ver)
	}
}

func TestPackageManagerLock(t *testing.T) {
	got, err := PackageManagerLock()
	if err != nil {
		t.Error(err)
	}

	if got {
		t.Errorf("Expected not to return a package lock: Got: %v, Error: %v", got, err)
	}
}

func TestSCQuery(t *testing.T) {
	// Test for a service that likely doesn't exist
	got, err := scQuery("csagent")
	if err != nil {
		t.Errorf("Expected nil error for non-existent service, got: %v", err)
	}
	if got {
		t.Errorf("Expected service not to exist: Got: %v", got)
	}

	// Test with empty service name
	got, err = scQuery("")
	if err == nil {
		t.Errorf("Expected error for empty service name")
	}
	if got {
		t.Errorf("Expected false result for empty service name: Got: %v", got)
	}

	// Test with a service that should exist
	got, err = scQuery("W32Time")
	if err != nil {
		t.Errorf("Error querying W32Time service: %v", err)
	}
	if !got {
		t.Errorf("Expected W32Time service to exist")
	}

	// Test with a non-existent service name
	got, err = scQuery("nonexistent_test_service")
	if err != nil {
		t.Errorf("Expected nil error for non-existent service, got: %v", err)
	}
	if got {
		t.Errorf("Expected service not to exist: Got: %v", got)
	}
}

func TestInstalledFalconVersion(t *testing.T) {
	got, err := InstalledFalconVersion("windows")
	if err != nil {
		t.Skip("Skipping test as Falcon Sensor is not installed")

	}

	if got == "" {
		t.Errorf("Expected version string, got empty string")
	}
}

// TestWinCreatePrivateDir verifies a missing directory is created, a directory owned by the
// current process is accepted, and a symlink, file, or directory owned by another account is
// rejected so the caller can switch to a fresh directory.
func TestWinCreatePrivateDir(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		setup   func(t *testing.T, dir string)
		wantErr error
	}{
		{
			name:  "creates missing directory",
			setup: func(*testing.T, string) {},
		},
		{
			name: "accepts existing directory",
			setup: func(t *testing.T, dir string) {
				if err := os.Mkdir(dir, 0700); err != nil {
					t.Fatalf("failed to seed directory: %v", err)
				}
			},
		},
		{
			name: "rejects symlink to a directory",
			setup: func(t *testing.T, dir string) {
				if err := os.Symlink(t.TempDir(), dir); err != nil {
					t.Skipf("creating symlinks requires elevated privileges or Developer Mode: %v", err)
				}
			},
			wantErr: ErrNotPrivateDir,
		},
		{
			name: "rejects regular file",
			setup: func(t *testing.T, dir string) {
				if err := os.WriteFile(dir, nil, 0600); err != nil {
					t.Fatalf("failed to seed file: %v", err)
				}
			},
			wantErr: ErrNotPrivateDir,
		},
		{
			name: "rejects directory owned by another account",
			setup: func(t *testing.T, dir string) {
				if err := os.Mkdir(dir, 0700); err != nil {
					t.Fatalf("failed to seed directory: %v", err)
				}
				// Setting an owner other than yourself requires SeRestorePrivilege, which an
				// elevated administrator or SYSTEM has.
				out, err := exec.Command("icacls", dir, "/setowner", "*S-1-5-19").CombinedOutput() // LOCAL SERVICE
				if err != nil {
					t.Skipf("cannot set another owner without SeRestorePrivilege: %v: %s", err, out)
				}
			},
			wantErr: ErrNotPrivateDir,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dir := filepath.Join(t.TempDir(), "falcon")
			tt.setup(t, dir)

			err := CreatePrivateDir(dir)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("CreatePrivateDir() error = %v, want %v", err, tt.wantErr)
			}

			if tt.wantErr == nil {
				if info, err := os.Lstat(dir); err != nil || !info.IsDir() {
					t.Errorf("expected %s to be a directory, got info=%v err=%v", dir, info, err)
				}
			}
		})
	}
}
