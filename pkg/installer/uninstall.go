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

		fc.uninstallSensor(fc.SensorConfig.MaintenanceToken)
	}
	slog.Info("Falcon Sensor has been uninstalled")
}

// installSensor installs the Falcon sensor using the appropriate package manager.
func (fc FalconInstaller) uninstallSensor(maintenanceToken string) {
	c := ""
	env := ""
	args := []string{} //nolint:staticcheck

	switch fc.OSType {
	case "linux":
		sensor := "falcon-sensor"

		if cmd, err := exec.LookPath("/usr/bin/dnf"); err == nil {
			c = cmd
			args = []string{"remove", "-q", "-y", sensor}
		} else if cmd, err := exec.LookPath("/usr/bin/yum"); err == nil {
			c = cmd
			args = []string{"remove", "-q", "-y", sensor}
		} else if cmd, err := exec.LookPath("/usr/bin/zypper"); err == nil {
			c = cmd
			args = []string{"remove", "--quiet", "-y", sensor}
		} else if cmd, err := exec.LookPath("/usr/bin/apt-get"); err == nil {
			c = cmd
			args = []string{"purge", "-y", sensor}
			env = "DEBIAN_FRONTEND=noninteractive"
		} else if cmd, err := exec.LookPath("/usr/bin/dpkg"); err == nil {
			c = cmd
			args = []string{"remove", "--qq", "-y", sensor}
			env = "DEBIAN_FRONTEND=noninteractive"
		} else {
			log.Fatalf("Unable to find expected linux package manager. Unsupported package manager: %v", err)
		}

		slog.Debug("Uninstall command being used for removal", "Command", c, "Args", args)
		stdout, stderr, err := installSensorWithRetry(c, env, args)
		if err != nil {
			log.Fatalf("Error running %s: %v, stdout: %s, stderr: %s", c, err, string(stdout), string(stderr))
		}

		slog.Debug("Removing Falcon Sensor", string(stdout), string(stderr))
	case "windows":
		uninstallArgs := []string{"/uninstall", "/quiet"}
		uninstallRegex := `^((WindowsSensor|FalconSensor_Windows).*\.)(exe)$`
		dir := "C:\\ProgramData\\Package Cache"

		if maintenanceToken != "" {
			uninstallArgs = append(uninstallArgs, fmt.Sprintf("MAINTENANCE_TOKEN=%s", maintenanceToken))
		}

		slog.Debug("Finding the Falcon Sensor uninstaller", "Directory", dir, "Regex", uninstallRegex)
		uninstaller, err := utils.FindFile(dir, uninstallRegex)
		if err != nil {
			log.Fatalf("Error finding the Windows Sensor uninstaller: %v", err)
		}

		slog.Debug("Running the Falcon Sensor uninstaller", "Uninstaller", uninstaller, "Args", uninstallArgs)
		stdout, stderr, err := utils.RunCmd(uninstaller, uninstallArgs)
		if err != nil {
			log.Fatalf("Error running %s: %v, stdout: %s, stderr: %s", uninstaller, err, string(stdout), string(stderr))
		}

		slog.Debug("Removing Falcon Sensor")
	case "macos":
		if maintenanceToken != "" {
			slog.Debug("Uninstalling the Falcon Sensor with maintenance token")
			if err := falconctl.SetWithMaintenanceTokenMacOS(fc.OSType, fc.macosArgHandler("uninstall"), maintenanceToken); err != nil {
				log.Fatalf("Error configuring Falcon sensor: %v", err)
			}
		} else {
			slog.Debug("Uninstalling the Falcon Sensor")
			if err := falconctl.Set(fc.OSType, fc.macosArgHandler("uninstall")); err != nil {
				log.Fatalf("Error configuring Falcon sensor: %v", err)
			}
		}
	default:
		log.Fatalf("Unable to begin package installation. Unsupported OS: %s", fc.OSType)
	}
}
