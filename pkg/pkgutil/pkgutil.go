package pkgutil

import (
	"fmt"
	"os/exec"

	"github.com/crowdstrike/falcon-installer/pkg/utils"
)

var pkgUtilCmnd = "/usr/sbin/pkgutil"

// IsPkgUtilInstalled checks if the macOS package manager is installed.
func IsPkgUtilInstalled() bool {
	if _, err := exec.LookPath(pkgUtilCmnd); err != nil {
		return false
	}
	return true
}

// Query queries the macOS package manager for the presence of a package.
func Query(name string) (bool, error) {
	args := []string{fmt.Sprintf("--pkgs=%s", name)}
	if _, stderr, err := utils.RunCmd(pkgUtilCmnd, args); err != nil {
		if len(string(stderr)) < 1 {
			return false, nil
		}
		return false, fmt.Errorf("Error running pkgutil --pkgs: %s", string(stderr))
	}

	return true, nil
}
