//go:build linux
// +build linux

package osutils

import (
	"testing"
)

func TestFalconInstalled(t *testing.T) {
	got, err := FalconInstalled("linux")
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
	got, err := RunningWithPrivileges("linux")
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
	os, ver, err := ReadEtcRelease("linux")
	if err != nil {
		t.Error(err)
	}

	if os == "" || ver == "" {
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
	got, err := packageManagerQuery("falcon-sensor")
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
