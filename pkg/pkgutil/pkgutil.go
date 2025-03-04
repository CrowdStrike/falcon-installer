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

package pkgutil

import (
	"fmt"
	"os/exec"

	"github.com/crowdstrike/falcon-installer/pkg/utils"
)

var pkgUtilCmd = "/usr/sbin/pkgutil"

// IsPkgUtilInstalled checks if the macOS package manager is installed.
func IsPkgUtilInstalled() bool {
	if _, err := exec.LookPath(pkgUtilCmd); err != nil {
		return false
	}
	return true
}

// Query queries the macOS package manager for the presence of a package.
func Query(name string) (bool, error) {
	if _, stderr, err := utils.RunCmd(pkgUtilCmd, []string{fmt.Sprintf("--pkgs=%s", name)}); err != nil {
		if len(string(stderr)) < 1 {
			return false, nil
		}
		return false, fmt.Errorf("Error running pkgutil --pkgs: %s", string(stderr))
	}

	return true, nil
}
