package systemd

import (
	"os/exec"
	"strings"
	"testing"
)

func skipSystemdTests(t *testing.T) {
	if _, err := exec.LookPath(systemctlCmd); err != nil {
		t.Skip("Skipping systemd tests since systemd is not installed")
	}
}

func TestRestartService(t *testing.T) {
	serviceName := "myservice"
	systemctlCmd = "noSystemCtl"
	err := RestartService(serviceName)
	if !strings.Contains(err.Error(), "Could not find systemctl") {
		t.Errorf("Unexpected error: %v", err)
	}

	systemctlCmd = "systemctl"

	// Skip systemctl restart if systemctl is not installed
	skipSystemdTests(t)

	err = RestartService(serviceName)
	errNoSystemctl := "Could not find systemctl: /usr/bin/systemctl"
	errRestartService := "Error restarting service myservice"
	if !strings.Contains(err.Error(), errNoSystemctl) && !strings.Contains(err.Error(), errRestartService) {
		t.Errorf("Unexpected error: %v", err)
	}
}
