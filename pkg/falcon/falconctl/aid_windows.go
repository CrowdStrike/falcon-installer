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

//go:build windows
// +build windows

package falconctl

import (
	"encoding/hex"
	"fmt"
	"log/slog"

	"golang.org/x/sys/windows/registry"
)

// GetAID retrieves the agent ID (AID) of the Falcon sensor from the Windows registry.
func GetAID() (string, error) {
	registryKeys := []string{
		"SYSTEM\\CrowdStrike\\{9b03c1d9-3138-44ed-9fae-d9f4c034b88d}\\{16e0423f-7058-48c9-a204-725362b67639}\\Default",
		"SYSTEM\\CurrentControlSet\\Services\\CSAgent\\Sim",
	}
	aid := ""
	var err error

	for _, regPath := range registryKeys {
		slog.Debug("Trying registry path:", "Path", regPath)
		aid, err = getBinaryRegistryValue(regPath)
		if aid != "" {
			return aid, nil
		}
	}

	return "", fmt.Errorf("Cannot read the registry value: %v", err)
}

// getBinaryRegistryValue reads a binary registry value and returns it as a string.
func getBinaryRegistryValue(reg string) (string, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, reg, registry.QUERY_VALUE)
	if err != nil {
		return "", err
	}
	defer k.Close()

	value, _, err := k.GetBinaryValue("AG")
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(value), nil
}
