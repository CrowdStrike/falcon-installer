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

// GetAID retrieves the Agent ID (AID) from the Falcon sensor.
func GetAID() (string, error) {
	switch runtime.GOOS {
	case "darwin", "macos":
		return getMacOSAID()
	case "linux":
		return getLinuxAID()
	default:
		return "", fmt.Errorf("unsupported OS for AID retrieval: %s", runtime.GOOS)
	}
}

// getMacOSAID retrieves the Agent ID from the Falcon sensor on macOS.
func getMacOSAID() (string, error) {
	stats, err := Get([]string{"stats"})
	if err != nil {
		return "", fmt.Errorf("failed to get sensor stats: %w", err)
	}

	for _, line := range strings.Split(stats, "\n") {
		if strings.Contains(line, "agentID") {
			parts := strings.Fields(line)
			if len(parts) < 2 {
				return "", fmt.Errorf("unexpected format in stats output: %s", line)
			}
			// Extract and normalize the AID
			return strings.ReplaceAll(strings.ToLower(parts[1]), "-", ""), nil
		}
	}

	return "", fmt.Errorf("agent ID not found in sensor stats")
}

// getLinuxAID retrieves the Agent ID from the Falcon sensor on Linux.
func getLinuxAID() (string, error) {
	output, err := Get([]string{"-g", "--aid"})
	if err != nil {
		return "", fmt.Errorf("failed to retrieve agent ID: %w", err)
	}

	// Parse the output to extract the AID
	parts := strings.Split(output, "\"")
	if len(parts) < 2 {
		return "", fmt.Errorf("unexpected format in AID output: %s", output)
	}

	return parts[1], nil
}
