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
	"testing"
)

func TestWinFalconInstalled(t *testing.T) {
	got, err := FalconInstalled("windows")
	if err != nil {
		t.Error(err)
	}

	if got {
		t.Errorf("Expected Falcon Sensor not to be installed: Got: %v, Error: %v", got, err)
	}

	scQueryCmnd = "noop.exe"
	got, err = FalconInstalled("windows")
	if err == nil {
		t.Errorf("Expected error: %v", err)
	}

	if got {
		t.Errorf("Expected Falcon Sensor not to be installed: Got: %v, Error: %v", got, err)
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
		if err.Error() != "You must run this program as an Administrator" {
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

func TestSCQuery(t *testing.T) {
	scQueryCmnd = "sc.exe"
	got, err := scQuery("csagent")
	if err != nil {
		t.Error(err)
	}

	if got {
		t.Errorf("Expected service not to be running: Got: %v, Error: %v", got, err)
	}

	got, err = scQuery("")
	if err == nil {
		t.Errorf("Expected error: %v", err)
	}

	if got {
		t.Errorf("Expected service not to be running: Got: %v, Error: %v", got, err)
	}

	got, err = scQuery("dnscache")
	if err != nil {
		t.Error(err)
	}

	if !got {
		t.Errorf("Expected service to be running: Got: %v, Error: %v", got, err)
	}

	scQueryCmnd = "noop.exe"
	got, err = scQuery("csagent")
	if err == nil {
		t.Errorf("Expected error: %v", err)
	}

	if got {
		t.Errorf("Expected service not to be running: Got: %v, Error: %v", got, err)
	}
}
