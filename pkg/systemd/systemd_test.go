//go:build linux
// +build linux

package systemd

import (
	"strings"
	"testing"
)

func TestRestartService(t *testing.T) {
	serviceName := "myservice"
	err := RestartService(serviceName)
	errNoSystemctl := "Could not find systemctl: /usr/bin/systemctl"
	errRestartService := "Error restarting service myservice"
	if !strings.Contains(err.Error(), errNoSystemctl) && !strings.Contains(err.Error(), errRestartService) {
		t.Errorf("Unexpected error: %v", err)
	}

	systemctlCmd = "noSystemCtl"
	err = RestartService(serviceName)
	if !strings.Contains(err.Error(), "Could not find systemctl") {
		t.Errorf("Unexpected error: %v", err)
	}
}
