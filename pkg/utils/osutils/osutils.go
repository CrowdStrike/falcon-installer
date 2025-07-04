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
	"path/filepath"
	"strconv"
	"strings"

	"github.com/crowdstrike/falcon-installer/pkg/dpkg"
	"github.com/crowdstrike/falcon-installer/pkg/pkgutil"
	"github.com/crowdstrike/falcon-installer/pkg/rpm"
)

// FalconInstalled checks if the Falcon Sensor is installed on the target OS.
func FalconInstalled(targetOS string) (bool, error) {
	falconInstalled := false
	pkgName := "falcon-sensor"

	switch targetOS {
	case "linux", "macos":
		if targetOS == "macos" {
			pkgName = "com.crowdstrike.falcon.*"
		}

		falconInstalled, err := packageManagerQuery(pkgName)
		if err != nil {
			return falconInstalled, fmt.Errorf("error querying package manager: %v", err)
		}

		return falconInstalled, nil
	case "windows":
		falconInstalled, err := scQuery("csagent")
		if err != nil {
			return falconInstalled, fmt.Errorf("error querying service manager: %v", err)
		}

		return falconInstalled, nil
	}

	return falconInstalled, fmt.Errorf("unable to determine if Falcon Sensor is installed and running. Unsupported OS: %s", targetOS)
}

// RunningWithPrivileges checks if the program is running with root/admin privileges.
func RunningWithPrivileges(targetOS string) (bool, error) {
	switch targetOS {
	case "linux", "macos":
		user := os.Getuid()
		if user != 0 {
			return false, fmt.Errorf("you must run this program as root")
		}

		return true, nil
	case "windows":
		if !isWindowsAdmin() {
			return false, fmt.Errorf("you must run this program as an Administrator")
		}

		return true, nil
	}

	return false, fmt.Errorf("cannot check if running as a privileged user. Unsupported OS: %s", targetOS)
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
			return "", "", fmt.Errorf("error reading %s: %w", linuxOsRelease, err)
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
	case "macos":
		return "macos", "", nil
	default:
		return "", "", fmt.Errorf("unable to determine operating system. Unsupported OS: %s", targetOS)
	}
}

// PackageManagerLock checks if a package manager is locked due to another install taking place.
func PackageManagerLock() (bool, error) {
	switch {
	case rpm.IsRpmInstalled():
		return isLockFileInUse("/var/lib/rpm/.rpm.lock")
	case dpkg.IsDpkgInstalled():
		// Check both lock files used by dpkg/apt
		lockMain, err := isLockFileInUse("/var/lib/dpkg/lock")
		if err != nil {
			return false, err
		}
		if lockMain {
			return lockMain, nil
		}

		// Also check the frontend lock
		lockFrontend, err := isLockFileInUse("/var/lib/dpkg/lock-frontend")
		if err != nil {
			return false, err
		}

		return lockFrontend, nil
	default:
		return false, nil
	}
}

// isLockFileInUse checks if a RPM or DPKG lock file is in use by another process on Linux.
func isLockFileInUse(lockFile string) (bool, error) {
	procDirs, err := os.ReadDir("/proc")
	if err != nil {
		return false, fmt.Errorf("error reading /proc: %v", err)
	}

	for _, procDir := range procDirs {
		if !procDir.IsDir() {
			continue
		}

		pid, err := strconv.Atoi(procDir.Name())
		if err != nil {
			continue // Not a process directory
		}

		fdPath := filepath.Join("/proc", strconv.Itoa(pid), "fd")
		files, err := os.ReadDir(fdPath)
		if err != nil {
			continue // Ignore errors reading file descriptors
		}

		for _, file := range files {
			link, err := os.Readlink(filepath.Join(fdPath, file.Name()))
			if err != nil {
				continue // Ignore errors reading symlinks
			}

			if link == lockFile {
				return true, nil
			}
		}
	}

	return false, nil
}

// packageManagerQuery queries the OS package manager for the presence of a package.
func packageManagerQuery(name string) (bool, error) {
	switch {
	case rpm.IsRpmInstalled():
		pkg, err := rpm.Query(name)
		if err != nil {
			return false, err
		}
		return pkg, nil
	case dpkg.IsDpkgInstalled():
		pkg, err := dpkg.Query(name)
		if err != nil {
			return false, err
		}
		return pkg, nil
	case pkgutil.IsPkgUtilInstalled():
		pkg, err := pkgutil.Query(name)
		if err != nil {
			return false, err
		}
		return pkg, nil
	}

	return false, fmt.Errorf("unsupported package manager for package query")
}
