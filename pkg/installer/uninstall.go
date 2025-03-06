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

package installer

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os/exec"

	"github.com/crowdstrike/falcon-installer/pkg/falcon"
	"github.com/crowdstrike/falcon-installer/pkg/falcon/falconctl"
	"github.com/crowdstrike/falcon-installer/pkg/utils"
	"github.com/crowdstrike/falcon-installer/pkg/utils/osutils"
	gofalcon "github.com/crowdstrike/gofalcon/falcon"
)

// Uninstall removes the Falcon Sensor from the target system.
func Uninstall(fc FalconInstaller) {
	falconInstalled, err := osutils.FalconInstalled(fc.OSType)
	if err != nil {
		log.Fatalf("Error checking if Falcon sensor is installed: %v", err)
	}

	// Uninstall the Falcon Sensor
	if falconInstalled {
		if fc.SensorConfig.MaintenanceToken == "" && (fc.AccessToken != "" || fc.ClientSecret != "") {
			client, err := gofalcon.NewClient(&gofalcon.ApiConfig{
				ClientId:          fc.ClientID,
				ClientSecret:      fc.ClientSecret,
				AccessToken:       fc.AccessToken,
				MemberCID:         fc.MemberCID,
				Cloud:             gofalcon.Cloud(fc.Cloud),
				Context:           context.Background(),
				UserAgentOverride: fc.UserAgent,
				TransportDecorator: func(t http.RoundTripper) http.RoundTripper {
					return falcon.NewFalconAPIRateLimitDecorator(t)
				},
			})
			if err != nil {
				log.Fatalf("Error creating Falcon client: %v", err)
			}

			slog.Debug("Maintenance token not provided. Retrieving the AID to get a maintenance token for uninstallation")
			aid, err := falconctl.GetAID()
			if err != nil {
				log.Fatalf("Error retrieving the AID: %v", err)
			}

			slog.Debug("Getting maintenance token for uninstallation using the AID", "AID", aid)
			fc.SensorConfig.MaintenanceToken = falcon.GetMaintenanceToken(client, aid)
		}

		if err := fc.uninstallSensor(fc.SensorConfig.MaintenanceToken); err != nil {
			log.Fatalf("Error uninstalling Falcon sensor: %v", err)
		}
	}
	slog.Info("Falcon Sensor has been uninstalled")
}

// UninstallSensor uninstalls the Falcon sensor using the appropriate method for the OS.
func (fc FalconInstaller) uninstallSensor(maintenanceToken string) error {
	slog.Debug("Starting Falcon sensor uninstallation", "osType", fc.OSType)

	switch fc.OSType {
	case "linux":
		return fc.uninstallLinuxSensor()
	case "windows":
		return fc.uninstallWindowsSensor(maintenanceToken)
	case "macos", "darwin":
		return fc.uninstallMacOSSensor(maintenanceToken)
	default:
		return fmt.Errorf("unsupported OS for uninstallation: %s", fc.OSType)
	}
}

// uninstallLinuxSensor uninstalls the Falcon sensor on Linux systems.
func (fc FalconInstaller) uninstallLinuxSensor() error {
	const sensorPackage = "falcon-sensor"

	// Define package managers in order of preference
	packageManagers := []struct {
		path    string
		args    []string
		envVars []string
	}{
		{"/usr/bin/dnf", []string{"remove", "-q", "-y", sensorPackage}, nil},
		{"/usr/bin/yum", []string{"remove", "-q", "-y", sensorPackage}, nil},
		{"/usr/bin/zypper", []string{"remove", "--quiet", "-y", sensorPackage}, nil},
		{"/usr/bin/apt-get", []string{"purge", "-y", sensorPackage}, []string{"DEBIAN_FRONTEND=noninteractive"}},
		{"/usr/bin/dpkg", []string{"remove", "--qq", "-y", sensorPackage}, []string{"DEBIAN_FRONTEND=noninteractive"}},
	}

	// Find the first available package manager
	for _, pm := range packageManagers {
		if cmd, err := exec.LookPath(pm.path); err == nil {
			slog.Debug("Using package manager for uninstallation",
				"command", cmd, "args", pm.args, "env", pm.envVars)

			stdout, stderr, err := installSensorWithRetry(cmd, pm.envVars, pm.args)
			if err != nil {
				return fmt.Errorf("failed to uninstall sensor: %w (stdout: %s, stderr: %s)",
					err, stdout, stderr)
			}

			slog.Debug("Successfully removed Falcon sensor",
				"stdout", string(stdout), "stderr", string(stderr))
			return nil
		}
	}

	return fmt.Errorf("no supported package manager found for uninstallation")
}

// uninstallWindowsSensor uninstalls the Falcon sensor on Windows systems.
func (fc FalconInstaller) uninstallWindowsSensor(maintenanceToken string) error {
	const (
		cacheDir       = "C:\\ProgramData\\Package Cache"
		uninstallRegex = `^((WindowsSensor|FalconSensor_Windows).*\.)(exe)$`
	)

	// Prepare uninstall arguments
	uninstallArgs := []string{"/uninstall", "/quiet"}

	// Find the uninstaller
	slog.Debug("Finding the Falcon Sensor uninstaller", "directory", cacheDir, "regex", uninstallRegex)
	uninstaller, err := utils.FindFile(cacheDir, uninstallRegex)
	if err != nil {
		return fmt.Errorf("failed to find Windows sensor uninstaller: %w", err)
	}

	slog.Debug("Running the Falcon Sensor uninstaller", "uninstaller", uninstaller, "args",
		uninstallArgs, "withMaintenanceToken", maintenanceToken != "")

	// Add the maintenance token to the uninstall arguments after the Debug logs are printed so that maintenanceToken is not logged
	if maintenanceToken != "" {
		uninstallArgs = append(uninstallArgs, fmt.Sprintf("MAINTENANCE_TOKEN=%s", maintenanceToken))
	}

	// Run the uninstaller
	stdout, stderr, err := utils.RunCmd(uninstaller, uninstallArgs)
	if err != nil {
		return fmt.Errorf("failed to uninstall sensor: %w (stdout: %s, stderr: %s)",
			err, string(stdout), string(stderr))
	}

	return nil
}

// uninstallMacOSSensor uninstalls the Falcon sensor on macOS systems.
func (fc FalconInstaller) uninstallMacOSSensor(maintenanceToken string) error {
	args := fc.buildMacOSArgs("uninstall")

	slog.Debug("Uninstalling the Falcon Sensor",
		"withMaintenanceToken", maintenanceToken != "")

	var err error
	if maintenanceToken != "" {
		err = falconctl.Set(args, falconctl.WithSensorMaintenanceTokenOption(maintenanceToken))
	} else {
		err = falconctl.Set(args)
	}

	if err != nil {
		return fmt.Errorf("failed to uninstall sensor: %w", err)
	}

	return nil
}
