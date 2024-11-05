package dpkg

import (
	"testing"
)

func skipDpkgTests(t *testing.T) {
	if !IsDpkgInstalled() {
		t.Skip("Skipping dpkg tests since dpkg is not installed")
	}
}

func TestIsDpkgInstalled(t *testing.T) {
	dpkgCmd = "/usr/bin/asdfasdf"
	got := IsDpkgInstalled()

	if got {
		t.Errorf("Expected %s not to exist: Got: %v", dpkgCmd, got)
	}

	dpkgCmd = "/usr/bin/dpkg"

	// Skip dpkg query if dpkg is not installed
	skipDpkgTests(t)

	got = IsDpkgInstalled()
	if !got {
		t.Errorf("Expected dpkg to be installed: Got: %v", got)
	}

}

func TestQuery(t *testing.T) {
	dpkgCmd = "/usr/bin/asdfasdf"
	got, err := Query("unknown")
	if err == nil {
		t.Errorf("Expected error: %v", err)
	}

	if got {
		t.Errorf("Expected package not to be installed: Got: %v, Error: %v", got, err)
	}

	dpkgCmd = "/usr/bin/dpkg"

	// Skip dpkg query if dpkg is not installed
	skipDpkgTests(t)

	got, err = Query("dpkg")
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

}
