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

//go:build !windows
// +build !windows

package osutils

import (
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

func testArch() string {
	if runtime.GOOS == "darwin" {
		return "macos"
	}
	return runtime.GOOS
}

func TestFalconInstalled(t *testing.T) {
	got, err := FalconInstalled(testArch())
	if err != nil {
		t.Error(err)
	}

	if got {
		t.Errorf("Expected Falcon Sensor not to be installed: Got: %v, Error: %v", got, err)
	}

	got, err = FalconInstalled("unknown")
	if err == nil {
		t.Errorf("Expected error %v", err)
	}

	if got {
		t.Errorf("Expected Falcon Sensor not to be installed: Got: %v, Error: %v", got, err)
	}
}

func TestRunningWithPrivileges(t *testing.T) {
	got, err := RunningWithPrivileges(testArch())
	if err == nil {
		t.Errorf("Expected error %v", err)
	}

	if got {
		t.Errorf("Expected not to be running with root privileges")
	}

	got, err = RunningWithPrivileges("unknown")
	if err == nil {
		t.Errorf("Expected error %v", err)
	}

	if got {
		t.Errorf("Expected not to be running with privileges on an unsupported OS: Got: %v, Error: %v", got, err)
	}
}

func TestReadEtcRelease(t *testing.T) {
	os, ver, err := ReadEtcRelease(testArch())
	if err != nil {
		t.Error(err)
	}

	if os == "linux" && ver == "" {
		t.Errorf("Expected to get os and version: Got: os: %s, ver: %s", os, ver)
	}

	os, ver, err = ReadEtcRelease("unknown")
	if err == nil {
		t.Errorf("Expected error %v", err)
	}

	if os != "" || ver != "" {
		t.Errorf("Expected empty string: Got: os: %s, ver: %s", os, ver)
	}
}

func TestPackageManagerQuery(t *testing.T) {
	pkgname := "falcon-sensor"

	if testArch() == "macos" {
		pkgname = "com.crowdstrike.falcon.*"
	}

	got, err := packageManagerQuery(pkgname)
	if err != nil {
		t.Error(err)
	}

	if got {
		t.Errorf("Expected Falcon Sensor not to be installed: Got: %v, Error: %v", got, err)
	}

	got, err = packageManagerQuery("unknown")
	if err != nil {
		t.Error(err)
	}

	if got {
		t.Errorf("Expected 'unknown' not to be installed: Got: %v, Error: %v", got, err)
	}
}

func TestPackageManagerLock(t *testing.T) {
	if testArch() != "linux" {
		t.Skip("Skipping test on macOS since /proc does not exist")
	}

	got, err := PackageManagerLock()
	if err != nil {
		t.Error(err)
	}

	if got {
		t.Errorf("Expected PackageManagerLock to return false: Got: %v, Error: %v", got, err)
	}
}

func TestIsLockFileInUse(t *testing.T) {
	if testArch() != "linux" {
		t.Skip("Skipping test on macOS since /proc does not exist")
	}

	got, err := isLockFileInUse("continue")
	if err != nil {
		t.Errorf("Expected error %v", err)
	}

	if got {
		t.Errorf("Expected IsLockFileInUse to return false: Got: %v, Error: %v", got, err)
	}

	got, err = isLockFileInUse("/dev/null")
	if err != nil {
		t.Error(err)
	}

	if !got {
		t.Errorf("Expected IsLockFileInUse to return true: Got: %v, Error: %v", got, err)
	}
}

func TestSCQueryExists(t *testing.T) {
	got, err := scQuery("csagent")
	if err == nil {
		t.Errorf("Expected error %v", err)
	}

	if got {
		t.Errorf("Expected Falcon Sensor not to be installed: Got: %v, Error: %v", got, err)
	}
}

func TestInstalledFalconVersion(t *testing.T) {
	got, err := InstalledFalconVersion(testArch())
	if err != nil {
		// Skip the test if Falcon is not installed
		installed, ierr := FalconInstalled(testArch())
		if ierr != nil {
			t.Error(ierr)
		}

		if installed {
			t.Error(err)
		}
	}

	// Since we're testing, we don't expect a specific version
	// We just want to make sure the function returns something reasonable
	if got == "" {
		t.Skip("Skipping test as Falcon Sensor is not installed")
	}

	// Check that the version string follows a typical version format
	if !strings.Contains(got, ".") {
		t.Errorf("Expected version string to contain periods, got: %s", got)
	}

	// Verify version string has at least two components (major.minor)
	parts := strings.Split(got, ".")
	if len(parts) < 2 {
		t.Errorf("Expected version string to have at least major and minor components, got: %s", got)
	}

	// Check that each component is a number
	for _, part := range parts {
		if _, err := strconv.Atoi(part); err != nil {
			t.Errorf("Expected version component to be a number, got: %s", part)
		}
	}

}

func TestScQuery(t *testing.T) {
	sc, err := scQuery("test_service")
	if err == nil {
		t.Errorf("Expected error on non-Windows platform, got nil")
	}

	if sc {
		t.Errorf("Expected false result on non-Windows platform, got: %v", sc)
	}
}

// TestPermsCreatesDir verifies the directory is created with 0700 permissions. The
// chown to root only succeeds when running as root, so a non-root run still creates and chmods
// the directory before returning the expected ownership error.
func TestPermsCreatesDir(t *testing.T) {
	t.Parallel()

	dir := t.TempDir() + "/falcon"
	err := EnsureDirPerms(dir)
	if os.Getuid() == 0 && err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("directory not created: %v", err)
	}
	if !info.IsDir() {
		t.Errorf("expected a directory")
	}
	if perm := info.Mode().Perm(); perm != 0700 {
		t.Errorf("expected permissions 0700, got %o", perm)
	}
}

// TestEnsureDirPermissions verifies a too-permissive existing directory is corrected to 0700.
func TestEnsureDirPermissions(t *testing.T) {
	t.Parallel()

	dir := t.TempDir() + "/loose"
	if err := os.Mkdir(dir, 0777); err != nil {
		t.Fatalf("failed to seed directory: %v", err)
	}
	// Defeat umask so the seeded perms are actually loose.
	if err := os.Chmod(dir, 0777); err != nil {
		t.Fatalf("failed to chmod seed directory: %v", err)
	}

	// chown to root only succeeds when running as root; the perm check below is what matters here.
	err := EnsureDirPerms(dir)
	if os.Getuid() != 0 {
		// Non-root cannot chown to root, so EnsureDirPerms returns an error after chmod succeeds.
		// Verify the chmod still took effect.
		if perm := mustPerm(t, dir); perm != 0700 {
			t.Errorf("expected permissions 0700, got %o", perm)
		}
		return
	}
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if perm := mustPerm(t, dir); perm != 0700 {
		t.Errorf("expected permissions 0700, got %o", perm)
	}

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		if stat.Uid != 0 {
			t.Errorf("expected owner uid 0, got %d", stat.Uid)
		}
	}
}

func mustPerm(t *testing.T, dir string) os.FileMode {
	t.Helper()
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	return info.Mode().Perm()
}
