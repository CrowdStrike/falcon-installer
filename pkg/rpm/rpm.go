package rpm

import (
	"fmt"
	"log"
	"os/exec"
	"strings"

	"github.com/crowdstrike/falcon-installer/pkg/utils"
)

const rpmCmd = "/usr/bin/rpm"

func Query(name string) (bool, error) {
	args := []string{"-q", name}

	if stdout, _, err := utils.RunCmd(exec.Command(rpmCmd, args...)); err != nil {
		if strings.Contains(string(stdout), "is not installed") {
			return false, nil
		}
		return false, fmt.Errorf("Error running rpm query: %v", err)
	}

	return true, nil
}

func IsRpmInstalled() bool {
	if _, err := exec.LookPath(rpmCmd); err != nil {
		return false
	}
	return true
}

func GpgKeyImport(gpgKeyFile string) {
	args := []string{"--import", gpgKeyFile}

	if _, _, err := utils.RunCmd(exec.Command(rpmCmd, args...)); err != nil {
		log.Fatalf("Error running rpm gpg key import: %v", err)
	}
}
