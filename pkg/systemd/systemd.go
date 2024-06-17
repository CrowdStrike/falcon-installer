package systemd

import (
	"log"
	"os/exec"

	"github.com/crowdstrike/falcon-installer/pkg/utils"
)

const systemctlCmd = "/usr/bin/systemctl"

func RestartService(name string) {
	if _, err := exec.LookPath(systemctlCmd); err == nil {
		args := []string{"restart", name}
		utils.RunCmd(exec.Command(systemctlCmd, args...))
	} else {
		log.Fatalf("Could not find systemctl: %s", systemctlCmd)
	}
}
