package systemd_test

import (
	"strings"
	"testing"

	"github.com/crowdstrike/falcon-installer/pkg/systemd"
)

func TestRestartService(t *testing.T) {
	serviceName := "myservice"
	err := systemd.RestartService(serviceName)
	errNoSystemctl := "Could not find systemctl: /usr/bin/systemctl"
	errRestartService := "Error restarting service myservice"
	if !strings.Contains(err.Error(), errNoSystemctl) && !strings.Contains(err.Error(), errRestartService) {
		t.Errorf("Unexpected error: %v", err)
	}
}
