// MIT License
//
// Copyright (c) 2024 CrowdStrike
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

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
	if !strings.Contains(err.Error(), "could not find systemctl") {
		t.Errorf("Unexpected error: %v", err)
	}

	systemctlCmd = "systemctl"

	// Skip systemctl restart if systemctl is not installed
	skipSystemdTests(t)

	err = RestartService(serviceName)
	errNoSystemctl := "could not find systemctl: /usr/bin/systemctl"
	errRestartService := "error restarting service myservice"
	if !strings.Contains(err.Error(), errNoSystemctl) && !strings.Contains(err.Error(), errRestartService) {
		t.Errorf("Unexpected error: %v", err)
	}
}
