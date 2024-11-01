//go:build linux
// +build linux

package dpkg

import (
	"testing"
)

func TestIsDpkgInstalled(t *testing.T) {
	got := IsDpkgInstalled()

	if !got {
		t.Errorf("Expected dpkg to be installed: Got: %v", got)
	}

	dpkgCmd = "/usr/bin/asdfasdf"
	got = IsDpkgInstalled()

	if got {
		t.Errorf("Expected %s not to exist: Got: %v", dpkgCmd, got)
	}
}

func TestQuery(t *testing.T) {
	dpkgCmd = "/usr/bin/dpkg"
	got, err := Query("dpkg")
	if err != nil {
		t.Error(err)
	}

	if !got {
		t.Errorf("Expected dpkg to be installed: Got: %v, Error: %v", got, err)
	}

	got, err = Query("unknown")
	if err != nil {
		t.Error(err)
	}

	if got {
		t.Errorf("Expected package not to be installed: Got: %v, Error: %v", got, err)
	}

	dpkgCmd = "/usr/bin/asdfasdf"
	got, err = Query("unknown")
	if err == nil {
		t.Errorf("Expected error: %v", err)
	}

	if got {
		t.Errorf("Expected package not to be installed: Got: %v, Error: %v", got, err)
	}
}
