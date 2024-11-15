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

func TestSCQueryExists(t *testing.T) {
	got, err := scQuery("csagent")
	if err == nil {
		t.Errorf("Expected error %v", err)
	}

	if got {
		t.Errorf("Expected Falcon Sensor not to be installed: Got: %v, Error: %v", got, err)
	}
}
