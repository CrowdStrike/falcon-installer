package pkgutil

import (
	"testing"
)

func skipPkgUtilTests(t *testing.T) {
	if !IsPkgUtilInstalled() {
		t.Skip("Skipping pkgutil tests since pkgutil is not installed")
	}
}

func TestIsPkgUtilInstalled(t *testing.T) {
	pkgUtilCmnd = "/usr/bin/asdfasdf"
	got := IsPkgUtilInstalled()

	if got {
		t.Errorf("Expected %s not to exist: Got: %v", pkgUtilCmnd, got)
	}

	pkgUtilCmnd = "/usr/sbin/pkgutil"

	// Skip pkgutil query if pkgutil is not installed
	skipPkgUtilTests(t)

	got = IsPkgUtilInstalled()
	if !got {
		t.Errorf("Expected pkgutil to be installed: Got: %v", got)
	}
}

func TestQuery(t *testing.T) {
	pkgUtilCmnd = "/usr/sbin/pkgutil"

	// Skip pkgutil query if pkgutil is not installed
	skipPkgUtilTests(t)

	got, err := Query("com.apple.pkg.Safari*")
	if err != nil {
		t.Error(err)
	}

	if !got {
		t.Errorf("Expected pkgutil to be installed: Got: %v, Error: %v", got, err)
	}

	got, err = Query("unknown")
	if err != nil {
		t.Error(err)
	}

	if got {
		t.Errorf("Expected package not to be installed: Got: %v, Error: %v", got, err)
	}
}
