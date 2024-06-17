package dpkg

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/crowdstrike/falcon-installer/pkg/utils"
)

const dpkgCmd = "/usr/bin/dpkg"

func IsDpkgInstalled() bool {
	if _, err := exec.LookPath(dpkgCmd); err != nil {
		return false
	}
	return true
}

func Query(name string) (bool, error) {
	args := []string{"-l", name}

	if _, stderr, err := utils.RunCmd(exec.Command(dpkgCmd, args...)); err != nil {
		if strings.Contains(string(stderr), "no packages found") {
			return false, nil
		}
		return false, fmt.Errorf("Error running dpkg query: %v", err)
	}

	return true, nil
}
