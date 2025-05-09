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
	"strings"

	"github.com/crowdstrike/falcon-installer/pkg/falcon"
	"github.com/crowdstrike/falcon-installer/pkg/falcon/falconctl"
	"github.com/crowdstrike/falcon-installer/pkg/utils"
	"github.com/crowdstrike/falcon-installer/pkg/utils/osutils"
	gofalcon "github.com/crowdstrike/gofalcon/falcon"
)

// Update will update the sensor version if a newer version is available or if the force flag is set when sensor policies are not in use.
func Update(fc FalconInstaller) {
	// Check if Falcon is installed
	falconInstalled, err := osutils.FalconInstalled(fc.OSType)
	if err != nil {
		log.Fatalf("error checking if Falcon sensor is installed: %v", err)
	}

	if !falconInstalled {
		log.Fatal("Falcon sensor is not installed, cannot update")
	}

	// Get the current version of the installed sensor
	currentVersion, err := osutils.InstalledFalconVersion(fc.OSType)
	if err != nil {
		log.Fatal(err)
	}

	slog.Debug("Currently installed Falcon sensor version", "version", currentVersion)

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

	// Query the CrowdStrike API for a suitable Falcon sensor
	sensor := falcon.QuerySuitableSensor(client, fc.OsName, fc.OsVersion, fc.OSType, fc.Arch, fc.SensorUpdatePolicyName, fc.SensorVersion)
	if sensor == nil {
		log.Fatalf("Could not find Falcon sensor for '%s' '%s'", fc.OsName, fc.OsVersion)
	}

	if matchAPIversion(currentVersion, fc.OSType) == *sensor.Version {
		log.Fatal("Falcon sensor is already up to date")
	}

	if fc.SensorConfig.MaintenanceToken == "" && (fc.AccessToken != "" || fc.ClientSecret != "") {
		slog.Debug("Maintenance token not provided. Retrieving the AID to get a maintenance token for update")
		aid, err := falconctl.GetAID()
		if err != nil {
			log.Fatalf("Error retrieving the AID: %v", err)
		}

		slog.Debug("Getting maintenance token for update using the AID", "AID", aid)
		fc.SensorConfig.MaintenanceToken = falcon.GetMaintenanceToken(client, aid)
	}

	slog.Debug("Found suitable Falcon sensor", "name", *sensor.Name, "version", *sensor.Version)
	// Download the Falcon sensor installer from the CrowdStrike API
	path := falcon.SensorDownload(client, sensor, fc.TmpDir, *sensor.Name)

	slog.Debug("Downloaded Falcon sensor installer", "path", path)

	// Update the current version
	err = fc.updateSensor(path, fc.SensorConfig.MaintenanceToken)
	if err != nil {
		log.Fatal(err)
	}

	slog.Info("Falcon sensor updated successfully")
}

// matchAPIversion compares the installed sensor version with the API version format.
func matchAPIversion(systemVersion string, os string) string {
	switch os {
	case "linux":
		// For Linux, we need to parse the version string to match API format of 7.24.17706
		// extract from the system version of 7.24.0-17706
		parts := strings.Split(systemVersion, "-")
		if len(parts) != 2 {
			return systemVersion // Return as-is if format doesn't match expected pattern

		}

		// Split the version part by "." to get individual components
		versionComponents := strings.Split(parts[0], ".")
		// If we have 3 components (e.g., "7.24.0"), we need to replace the last one with the build number
		if len(versionComponents) == 3 {
			return versionComponents[0] + "." + versionComponents[1] + "." + parts[1]
		}

		return systemVersion
	default:
		// For other OSes, the system version is 7.23.19507.0 and the API version is 7.23.19507
		// We need to remove the trailing ".0" if present
		if strings.HasSuffix(systemVersion, ".0") {
			systemVersion, _ = strings.CutSuffix(systemVersion, ".0")
			return systemVersion
		}
		return systemVersion
	}

}

// updateSensor is a helper function that updates the current sensor package to the latest or specified version.
func (fc FalconInstaller) updateSensor(path string, maintenanceToken string) error {
	slog.Debug("Starting Falcon sensor update", "osType", fc.OSType)

	switch fc.OSType {
	case "linux":
		return fc.updateLinuxSensor(path, maintenanceToken)
	case "windows":
		return fc.updateWindowsSensor(path, maintenanceToken)
	case "macos", "darwin":
		return fc.updateMacOSSensor(path)
	default:
		return fmt.Errorf("unsupported OS for sensor update: %s", fc.OSType)
	}
}

// updateLinuxSensor updates the Falcon sensor on Linux systems.
func (fc FalconInstaller) updateLinuxSensor(path string, maintenanceToken string) error {
	// Define package managers in order of preference
	packageManagers := []struct {
		path    string
		args    []string
		envVars []string
	}{
		{"/usr/bin/dnf", []string{"update", "-q", "-y", path}, nil},
		{"/usr/bin/yum", []string{"update", "-q", "-y", path}, nil},
		{"/usr/bin/zypper", []string{"update", "--quiet", "-y", path}, nil},
		{"/usr/bin/apt-get", []string{"install", "-y", path}, []string{"DEBIAN_FRONTEND=noninteractive"}},
		{"/usr/bin/dpkg", []string{"--install", path}, []string{"DEBIAN_FRONTEND=noninteractive"}},
	}

	// run falconctl with maintenance token
	if maintenanceToken != "" {
		err := falconctl.Set([]string{"-s", fmt.Sprintf("--maintenance-token=%s", maintenanceToken)})
		if err != nil {
			return fmt.Errorf("failed to set maintenance token: %w", err)
		}
	}

	// Find the first available package manager
	for _, pm := range packageManagers {
		if cmd, err := exec.LookPath(pm.path); err == nil {
			slog.Debug("Using package manager for updating",
				"command", cmd, "args", pm.args, "env", pm.envVars)

			stdout, stderr, err := installSensorWithRetry(cmd, pm.envVars, pm.args)
			if err != nil {
				return fmt.Errorf("failed to update the sensor: %w (stdout: %s, stderr: %s)",
					err, stdout, stderr)
			}

			slog.Debug("Successfully updated Falcon sensor",
				"stdout", string(stdout), "stderr", string(stderr))
			return nil
		}
	}

	return fmt.Errorf("no supported package manager found for updating the sensor")
}

// updateWindowsSensor updates the Falcon sensor on Windows systems.
func (fi FalconInstaller) updateWindowsSensor(path string, maintenanceToken string) error {
	args := []string{"/silent", "/upgrade"}
	if maintenanceToken != "" {
		args = append(args, fmt.Sprintf("/maintenance_token=%s", maintenanceToken))
	}
	slog.Debug("Updating Falcon sensor on Windows", "installer", path, "args", args)

	stdout, stderr, err := utils.RunCmd(path, args)
	if err != nil {
		return fmt.Errorf("failed to update the sensor: %w (stdout: %s, stderr: %s)",
			err, string(stdout), string(stderr))
	}

	return nil
}

// updateMacOSSensor updates the Falcon sensor on MacOS systems.
func (fc FalconInstaller) updateMacOSSensor(path string) error {
	return fc.installMacOSSensor(path)
}
