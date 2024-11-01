package rpm

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/crowdstrike/falcon-installer/pkg/utils"
)

var rpmCmd = "/usr/bin/rpm"

// Query checks if a package is installed e.g. `rpm -q <package>`.
func Query(name string) (bool, error) {
	args := []string{"-q", name}

	if stdout, _, err := utils.RunCmd(rpmCmd, args); err != nil {
		if strings.Contains(string(stdout), "is not installed") {
			return false, nil
		}
		return false, fmt.Errorf("Error running rpm query: %v", err)
	}

	return true, nil
}

// IsRpmInstalled checks if the rpm command is installed.
func IsRpmInstalled() bool {
	if _, err := exec.LookPath(rpmCmd); err != nil {
		return false
	}
	return true
}

// GpgKeyImport imports a gpg key into the rpm keyring.
func GpgKeyImport(gpgKeyFile string) error {
	args := []string{"--import", gpgKeyFile}

	if _, _, err := utils.RunCmd(rpmCmd, args); err != nil {
		return fmt.Errorf("Error running rpm gpg key import: %v", err)
	}

	return nil
}
