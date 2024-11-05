package rpm

import (
	"testing"
)

func skipRpmTests(t *testing.T) {
	if !IsRpmInstalled() {
		t.Skip("Skipping rpm tests since rpm is not installed")
	}
}

func TestIsRpmInstalled(t *testing.T) {
	rpmCmd = "/usr/bin/asdfasdf"
	got := IsRpmInstalled()
	if got {
		t.Errorf("Expected %s not to exist: Got: %v", rpmCmd, got)
	}

	rpmCmd = "/usr/bin/rpm"

	// Skip rpm query if rpm is not installed
	skipRpmTests(t)

	got = IsRpmInstalled()
	if !got {
		t.Errorf("Expected rpm to be installed: Got: %v", got)
	}

}

func TestQuery(t *testing.T) {
	rpmCmd = "/usr/bin/asdfasdf"
	got, err := Query("unknown")
	if err == nil {
		t.Errorf("Expected error: %v", err)
	}

	if got {
		t.Errorf("Expected package not to be installed: Got: %v, Error: %v", got, err)
	}

	rpmCmd = "/usr/bin/rpm"

	// Skip rpm query if rpm is not installed
	skipRpmTests(t)

	got, err = Query("rpm")
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

}

func TestGpgKeyImport(t *testing.T) {
	rpmCmd = "/usr/bin/rpm"

	// Skip rpm gpg test if rpm is not installed
	skipRpmTests(t)

	err := GpgKeyImport("key")
	if err == nil {
		t.Errorf("Expected error: %v", err)
	}
}
