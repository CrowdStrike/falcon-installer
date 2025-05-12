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

package dpkg

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/crowdstrike/falcon-installer/pkg/utils"
)

var dpkgCmd = "/usr/bin/dpkg"

// IsDpkgInstalled checks if the dpkg command is installed.
func IsDpkgInstalled() bool {
	if _, err := exec.LookPath(dpkgCmd); err != nil {
		return false
	}
	return true
}

// Query checks if a package is installed using `dpkg -l <package>`.
func Query(name string) (bool, error) {
	stdout, stderr, err := utils.RunCmd(dpkgCmd, []string{"-l", name})
	if err != nil {
		if strings.Contains(string(stderr), "no packages found") {
			return false, nil
		}
		return false, fmt.Errorf("error running dpkg query: %w", err)
	}

	return strings.Contains(string(stdout), name), nil
}

// GetVersion returns the version of a package using `dpkg -s <package>`.
func GetVersion(name string) (string, error) {
	stdout, stderr, err := utils.RunCmd(dpkgCmd, []string{"-s", name})
	if err != nil {
		if strings.Contains(string(stderr), "no packages found") || strings.Contains(string(stderr), "not installed") {
			return "", fmt.Errorf("package %s is not installed", name)

		}
		return "", fmt.Errorf("error getting package version: %w", err)
	}

	// Parse the output to extract the version
	lines := strings.Split(string(stdout), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "Version:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "Version:")), nil
		}
	}

	return "", fmt.Errorf("version not found for package %s", name)
}
