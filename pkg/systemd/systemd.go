package systemd

import (
	"fmt"
	"os/exec"

	"github.com/crowdstrike/falcon-installer/pkg/utils"
)

const systemctlCmd = "/usr/bin/systemctl"

// RestartService restarts a systemd service
func RestartService(name string) error {
	if _, err := exec.LookPath(systemctlCmd); err != nil {
		return fmt.Errorf("Could not find systemctl: %s", systemctlCmd)
	}

	args := []string{"restart", name}
	if _, _, err := utils.RunCmd(systemctlCmd, args); err != nil {
		return fmt.Errorf("Error restarting service %s: %v", name, err)
	}

	return nil
}
