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

package osutils

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/crowdstrike/falcon-installer/pkg/dpkg"
	"github.com/crowdstrike/falcon-installer/pkg/rpm"
	"github.com/crowdstrike/falcon-installer/pkg/utils"
)

var scQueryCmnd = "sc.exe"

// FalconInstalled checks if the Falcon Sensor is installed on the target OS.
func FalconInstalled(targetOS string) (bool, error) {
	falconInstalled := false

	switch targetOS {
	case "linux":
		falconInstalled, err := packageManagerQuery("falcon-sensor")
		if err != nil {
			return falconInstalled, fmt.Errorf("Error querying package manager: %v", err)
		}

		return falconInstalled, nil
	case "windows":
		falconInstalled, err := scQuery("csagent")
		if err != nil {
			return falconInstalled, fmt.Errorf("Error querying service manager: %v", err)
		}

		return falconInstalled, nil
	}

	return falconInstalled, fmt.Errorf("Unable to determine if Falcon Sensor is installed and running. Unsupported OS: %s", targetOS)
}

// RunningWithPrivileges checks if the program is running with root/admin privileges.
func RunningWithPrivileges(targetOS string) (bool, error) {
	switch targetOS {
	case "linux", "macos":
		user := os.Getuid()
		if user != 0 {
			return false, fmt.Errorf("You must run this program as root")
		}

		return true, nil
	case "windows":
		if !isWindowsAdmin() {
			return false, fmt.Errorf("You must run this program as an Administrator")
		}

		return true, nil
	}

	return false, fmt.Errorf("Cannot check if running as a privileged user. Unsupported OS: %s", targetOS)
}

// IsWindowsAdmin checks if the user is running as an Administrator on Windows.
func isWindowsAdmin() bool {
	_, err := os.Open("\\\\.\\PHYSICALDRIVE0")
	return err == nil
}

// ReadEtcRelease reads the /etc/os-release file on Linux and returns the OS name and version.
func ReadEtcRelease(targetOS string) (osName, osVersion string, err error) {
	switch targetOS {
	case "linux":
		linuxOsRelease := "/etc/os-release"
		data, err := os.ReadFile(linuxOsRelease)
		if err != nil {
			return "", "", fmt.Errorf("Error reading %s: %w", linuxOsRelease, err)
		}

		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "ID=") {
				osName = strings.Trim(strings.TrimPrefix(line, "ID="), "\"")
			} else if strings.HasPrefix(line, "VERSION_ID=") {
				osVersion = strings.Trim(strings.TrimPrefix(line, "VERSION_ID="), "\"")
			}
		}

		return osName, osVersion, nil
	case "windows":
		return "windows", "", nil
	default:
		return "", "", fmt.Errorf("Unable to determine operating system. Unsupported OS: %s", targetOS)
	}
}

// packageManagerQuery queries the linux package manager for the presence of a package.
func packageManagerQuery(name string) (bool, error) {
	if rpm.IsRpmInstalled() {
		pkg, err := rpm.Query(name)
		if err != nil {
			return false, err
		}
		return pkg, nil
	} else if dpkg.IsDpkgInstalled() {
		pkg, err := dpkg.Query(name)
		if err != nil {
			return false, err
		}
		return pkg, nil
	}

	return false, fmt.Errorf("Unsupported package manager for package query")
}

// scQuery queries the Windows service manager for the presence of a service.
func scQuery(name string) (bool, error) {
	var err error
	cmd, err := exec.LookPath(scQueryCmnd)
	if err != nil {
		return false, fmt.Errorf("Unable to find sc.exe: %v", err)
	}

	args := []string{"query", name}
	if stdout, _, err := utils.RunCmd(cmd, args); err != nil {
		if strings.Contains(string(stdout), "The specified service does not exist as an installed service") {
			return false, nil
		}
		return false, fmt.Errorf("Error running sc query: %v", err)
	}

	return true, nil
}
