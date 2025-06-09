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
	"runtime"
	"strconv"
	"strings"
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
