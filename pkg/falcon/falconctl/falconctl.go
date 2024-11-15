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

package falconctl

import (
	"fmt"
	"log/slog"
	"os/exec"

	"github.com/crowdstrike/falcon-installer/pkg/utils"
)

// cliConfig returns the path to the Falcon sensor command line interface based on the OS type.
func cliConfig(osType string) string {
	switch osType {
	case "macos", "darwin":
		return "/Applications/Falcon.app/Contents/Resources/falconctl"
	case "windows":
		return "C:\\Program Files\\CrowdStrike\\CSSensorSettings.exe"
	default:
		return "/opt/CrowdStrike/falconctl"
	}
}

// Set configures the Falcon sensor using the OS-specific command.
func Set(osType string, args []string) error {
	return configureSensor(cliConfig(osType), args)
}

// Get retrieves the Falcon sensor settings using the OS-specific command.
func Get(osType string, args []string) (string, error) {
	return getSensorSettings(cliConfig(osType), args)
}

// configureSensor configures the Falcon sensor using the OS-specific command.
func configureSensor(falconCtlCmd string, args []string) error {
	slog.Debug("Configuring Falcon sensor", "Command", falconCtlCmd, "Args", args)

	if _, err := exec.LookPath(falconCtlCmd); err != nil {
		return fmt.Errorf("Could not find falcon command: %s: %v", falconCtlCmd, err)
	}

	if _, stderr, err := utils.RunCmd(falconCtlCmd, args); err != nil {
		return fmt.Errorf("Error running falcon command: %v, stderr: %s", err, string(stderr))
	}

	return nil
}

// getSensorSettings using the sensor command line interface.
func getSensorSettings(falconCtlCmd string, args []string) (string, error) {
	slog.Debug("Getting sensor settings", "Command", falconCtlCmd, "Args", args)

	if _, err := exec.LookPath(falconCtlCmd); err != nil {
		return "", fmt.Errorf("Could not find falcon command: %s: %v", falconCtlCmd, err)
	}

	stdout, stderr, err := utils.RunCmd(falconCtlCmd, args)
	if err != nil {
		return "", fmt.Errorf("Error running falcon command: %v, stderr: %s", err, string(stderr))
	}

	return string(stdout), nil
}
