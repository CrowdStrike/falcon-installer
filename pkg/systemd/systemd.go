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
	"fmt"
	"os/exec"

	"github.com/crowdstrike/falcon-installer/pkg/utils"
)

var systemctlCmd = "systemctl"

// RestartService restarts a systemd service.
func RestartService(name string) error {
	if systemctlCmd, err := exec.LookPath(systemctlCmd); err != nil {
		return fmt.Errorf("Could not find systemctl: %s, %v", systemctlCmd, err)
	}

	args := []string{"restart", name}
	if _, _, err := utils.RunCmd(systemctlCmd, args); err != nil {
		return fmt.Errorf("Error restarting service %s: %v", name, err)
	}

	return nil
}
