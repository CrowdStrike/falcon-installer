//go:build linux
// +build linux

package rpm

import (
	"testing"
)

func TestIsRpmInstalled(t *testing.T) {
	got := IsRpmInstalled()
	if !got {
		t.Errorf("Expected rpm to be installed: Got: %v", got)
	}

	rpmCmd = "/usr/bin/asdfasdf"
	got = IsRpmInstalled()
	if got {
		t.Errorf("Expected %s not to exist: Got: %v", rpmCmd, got)
	}
}

func TestQuery(t *testing.T) {
	rpmCmd = "/usr/bin/rpm"
	got, err := Query("rpm")
	if err != nil {
		t.Error(err)
	}

	if !got {
		t.Errorf("Expected rpm to be installed: Got: %v, Error: %v", got, err)
	}

	got, err = Query("unknown")
	if err != nil {
		t.Error(err)
	}

	if got {
		t.Errorf("Expected package not to be installed: Got: %v, Error: %v", got, err)
	}

	rpmCmd = "/usr/bin/asdfasdf"
	got, err = Query("unknown")
	if err == nil {
		t.Errorf("Expected error: %v", err)
	}

	if got {
		t.Errorf("Expected package not to be installed: Got: %v, Error: %v", got, err)
	}
}

func TestGpgKeyImport(t *testing.T) {
	rpmCmd = "/usr/bin/rpm"
	err := GpgKeyImport("key")
	if err == nil {
		t.Errorf("Expected error: %v", err)
	}
}
