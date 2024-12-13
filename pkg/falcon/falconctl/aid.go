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

//go:build !windows
// +build !windows

package falconctl

import (
	"fmt"
	"runtime"
	"strings"
)

// GetAID retrieves the agent ID (AID) from the Falcon sensor.
func GetAID() (string, error) {
	switch runtime.GOOS {
	case "darwin":
		stats, err := Get("macos", []string{"stats"})
		if err != nil {
			return "", fmt.Errorf("Could not get stats: %v", err)
		}

		for _, line := range strings.Split(stats, "\n") {
			if strings.Contains(line, "agentID") {
				return strings.ReplaceAll(strings.ToLower(strings.Split(line, " ")[1]), "-", ""), nil
			}
		}
		return "", fmt.Errorf("Unsupported OS: %v", runtime.GOOS)
	case "linux":
		aid := ""
		var err error
		if aid, err = Get("linux", []string{"-g", "--aid"}); err != nil {
			return "", fmt.Errorf("Error retrieving Falcon sensor settings: %v", err)
		}
		return strings.Split(aid, "\"")[1], nil
	default:
		return "", fmt.Errorf("Unsupported OS: %v", runtime.GOOS)
	}
}
