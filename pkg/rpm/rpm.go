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

package rpm

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/crowdstrike/falcon-installer/pkg/utils"
)

var rpmCmd = "/usr/bin/rpm"

// Query checks if a package is installed e.g. `rpm -q <package>`.
func Query(name string) (bool, error) {
	if stdout, _, err := utils.RunCmd(rpmCmd, []string{"-q", name}); err != nil {
		if strings.Contains(string(stdout), "is not installed") {
			return false, nil
		}
		return false, fmt.Errorf("error running rpm query: %v", err)
	}

	return true, nil
}

// GetVersion returns the version of an installed package.
func GetVersion(name string) ([]string, error) {
	stdout, _, err := utils.RunCmd(rpmCmd, []string{"-q", "--qf", "[%{VERSION} %{RELEASE}]", name})
	if err != nil {
		return []string{}, fmt.Errorf("error getting package version: %v", err)

	}

	rpmVer := strings.TrimSuffix(string(stdout), filepath.Ext(string(stdout)))
	return strings.Split(rpmVer, " "), nil
}

// IsRpmInstalled checks if the rpm command is installed.
func IsRpmInstalled() bool {
	if _, err := exec.LookPath(rpmCmd); err != nil {
		return false
	}
	return true
}

// GpgKeyImport imports a gpg key into the rpm keyring.
func GpgKeyImport(gpgKeyFile string) error {
	if _, _, err := utils.RunCmd(rpmCmd, []string{"--import", gpgKeyFile}); err != nil {
		return fmt.Errorf("error running rpm gpg key import: %v", err)
	}

	return nil
}
