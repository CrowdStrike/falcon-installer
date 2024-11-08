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

// Query checks if a package is installed e.g. `dpkg -l <package>`.
func Query(name string) (bool, error) {
	args := []string{"-l", name}

	if _, stderr, err := utils.RunCmd(dpkgCmd, args); err != nil {
		if strings.Contains(string(stderr), "no packages found") {
			return false, nil
		}
		return false, fmt.Errorf("Error running dpkg query: %v", err)
	}

	return true, nil
}
