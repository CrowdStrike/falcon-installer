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
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/crowdstrike/falcon-installer/pkg/falcon"
	"github.com/crowdstrike/falcon-installer/pkg/falcon/falconctl"
	"github.com/crowdstrike/falcon-installer/pkg/rpm"
	"github.com/crowdstrike/falcon-installer/pkg/systemd"
	"github.com/crowdstrike/falcon-installer/pkg/utils"
	"github.com/crowdstrike/falcon-installer/pkg/utils/osutils"
	gofalcon "github.com/crowdstrike/gofalcon/falcon"
)

var (
	windowsFalconArgMap = map[string]string{
		"cid":                "CID",
		"provisioning-token": "ProvToken",
		"tags":               "GROUPING_TAGS",
		"apd":                "PROXYDISABLE",
		"aph":                "APP_PROXYNAME",
		"app":                "APP_PROXYPORT",
	}
)

// FalconSensorCLI is the configuration for the Falcon sensor CLI args.
type FalconSensorCLI struct {
	// CID is the customer ID for the sensor to use when communicating with CrowdStrike.
	CID string
	// ProxyDisable will disable the sensor's proxy settings.
	ProxyDisable bool
	// ProxyHost is the proxy host for the sensor to use when communicating with CrowdStrike.
	ProxyHost string
	// ProxyPort is the proxy port for the sensor to use when communicating with CrowdStrike.
	ProxyPort string
	// Tags is a comma separated list of tags for sensor grouping.
	Tags string
	// MaintenanceToken is the token used to perform maintenance on the sensor when Tamper Protection is enabled.
	MaintenanceToken string
	// ProvisioningToken is the token used to provision the sensor. If not provided, the API will attempt to retrieve a token.
	ProvisioningToken string
	// DisableProvisioningWait allows the Windows installer more provisioning time when communicating with CrowdStrike. Windows only.
	DisableProvisioningWait bool
	// ProvisioningWaitTime is the time in milliseconds to wait for the sensor to provision. Windows only.
	ProvisioningWaitTime uint64
	// PACURL is the proxy auto-config URL for the sensor to use when communicating with CrowdStrike. Windows only.
	PACURL string
	// Restart will allow the system to restart if necessary after sensor installation. Windows only.
	Restart bool
	// NoStart will prevent the sensor from starting after installation until a reboot occurs. Windows only.
	NoStart bool
	// VDI will enable virtual desktop infrastructure mode. Windows only.
	VDI bool
}

// FalconInstaller is the configuration for the Falcon installer.
type FalconInstaller struct {
	// ClientID is the client ID for accessing CrowdStrike Falcon Platform.
	ClientID string
	// ClientSecret is the client secret for accessing CrowdStrike Falcon Platform.
	ClientSecret string
	// AccessToken is the access token for accessing CrowdStrike Falcon Platform.
	AccessToken string
	// MemberCID is the member CID for MSSP (for cases when OAuth2 authenticates multiple CIDs).
	MemberCID string
	// Cloud is the Falcon cloud abbreviation (us-1, us-2, eu-1, us-gov-1). Defaults to autodiscover.
	Cloud string
	// SensorUpdatePolicyName is the sensor update policy name to use for sensor installation.
	SensorUpdatePolicyName string
	// TmpDir is the temporary directory to use for downloading the sensor.
	TmpDir string
	// Arch is the architecture to install the sensor on.
	Arch string
	// OSType is the type of operating system to install the sensor on e.g. linux, windows, macos, etc.
	OSType string
	// OsName is the name of the OS to use when querying for the sensor.
	OsName string
	// OsVersion is the version of the OS to use when querying for the sensor.
	OsVersion string
	// GpgKeyFile is the path to the GPG key file to use for importing the key. Linux only.
	GpgKeyFile string
	// UserAgent is the user agent string to use when making API requests.
	UserAgent string
	// ConfigureImage will configure the sensor on the image. Linux only.
	ConfigureImage bool

	// SensorConfig is the configuration for the Falcon sensor CLI args.
	SensorConfig FalconSensorCLI
}

// Run installs the Falcon sensor on the system.
func Run(fc FalconInstaller) {
	falconInstalled, err := osutils.FalconInstalled(fc.OSType)
	if err != nil {
		log.Fatalf("Error checking if Falcon sensor is installed: %v", err)
	}

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

	falconArgs := fc.buildInstallerArgs()

	// Get the provisioning token from the API if not provided
	if fc.SensorConfig.ProvisioningToken == "" {
		fc.SensorConfig.ProvisioningToken = falcon.GetProvisioningToken(client)
		if fc.SensorConfig.ProvisioningToken != "" {
			falconArgs = append(falconArgs, fc.formatArg("provisioning-token", fc.SensorConfig.ProvisioningToken))
		}
	}

	if !falconInstalled {
		if rpm.IsRpmInstalled() {
			gpgKey := fc.GpgKeyFile
			slog.Info("Installing CrowdStrike Falcon GPG key")

			if gpgKey != "" {
				slog.Debug("Using provided GPG key", "GPG Key", gpgKey)
			} else {
				gpgKey = fmt.Sprintf("%s%s%s", fc.TmpDir, string(os.PathSeparator), "falcon-gpg-key")
				err = os.WriteFile(gpgKey, []byte(gpgPublicKey), 0600)
				if err != nil {
					log.Fatalf("Error writing GPG key to file: %v", err)
				}
				slog.Debug("Using embedded GPG key", "GPG Key", gpgKey, "Key", gpgPublicKey)
			}

			err = rpmGpgKeyRetryImport(gpgKey)
			if err != nil {
				log.Fatalf("Error importing GPG key: %v", err)
			}
		}

		// Get the Falcon CID from the API if not provided
		if fc.SensorConfig.CID == "" {
			fc.SensorConfig.CID, err = falcon.GetCID(context.Background(), client)
			if err != nil {
				log.Fatalf("Error getting Falcon CID: %v", err)
			}
			slog.Debug("Found suitable Falcon Customer ID (CID)", "CID", fc.SensorConfig.CID)
			falconArgs = append(falconArgs, fc.formatArg("cid", fc.SensorConfig.CID))
		}

		// Query the CrowdStrike API for a suitable Falcon sensor
		sensor := falcon.QuerySuitableSensor(client, fc.OsName, fc.OsVersion, fc.OSType, fc.Arch, fc.SensorUpdatePolicyName, "latest")
		if sensor == nil {
			log.Fatalf("Could not find Falcon sensor for '%s' '%s'", fc.OsName, fc.OsVersion)
		}

		// Download the Falcon sensor installer from the CrowdStrike API
		path := falcon.SensorDownload(client, sensor, fc.TmpDir, *sensor.Name)

		slog.Info("Starting Falcon sensor installation")
		err = fc.installSensor(path)
		if err != nil {
			log.Fatalf("Error installing Falcon sensor: %v", err)
		}
	} else {
		slog.Info("Sensor is already installed. Skipping download and installation")
	}

	switch fc.OSType {
	case "linux":
		if len(falconArgs) > 1 {
			if err := falconctl.Set(falconArgs); err != nil {
				log.Fatalf("Error configuring Falcon sensor: %v", err)
			}
		} else {
			slog.Info("Skipping Falcon sensor configuration. No additional configuration required")
		}

		// Restart Falcon sensor service if it was installed
		if !falconInstalled {
			if err := systemd.RestartService("falcon-sensor"); err != nil {
				log.Fatalf("Error restarting Falcon sensor service: %v", err)
			}
		}
	case "macos":
		if !falconInstalled {
			if err := falconctl.Set(fc.buildMacOSArgs("license")); err != nil {
				if !strings.Contains(err.Error(), "Computer needs to be rebooted first") {
					log.Fatalf("Error configuring Falcon sensor: %v", err)
				}

				slog.Debug("Loading Falcon sensor kernel extension")
				if err := falconctl.Set(fc.buildMacOSArgs("load")); err != nil {
					log.Fatalf("Error configuring Falcon sensor: %v", err)
				}
			}
		} else if fc.SensorConfig.Tags != "" {
			if err := falconctl.Set(fc.buildMacOSArgs("grouping-tags")); err != nil {
				log.Fatalf("Error configuring Falcon sensor: %v", err)
			}

			if err := falconctl.Set(fc.buildMacOSArgs("unload")); err != nil {
				log.Fatalf("Error configuring Falcon sensor: %v", err)
			}

			if err := falconctl.Set(fc.buildMacOSArgs("load")); err != nil {
				log.Fatalf("Error configuring Falcon sensor: %v", err)
			}
		} else {
			slog.Info("Skipping Falcon sensor configuration. No additional configuration required")
		}

	}

	if !falconInstalled {
		slog.Info("Falcon sensor installation complete")
	}

	if fc.ConfigureImage && fc.OSType != "windows" {
		slog.Info("Configuring Falcon sensor for the image")
		if err := fc.configureSensorImage(); err != nil {
			log.Fatalf("Error configuring Falcon sensor for the image: %v", err)
		}
		slog.Info("Sensor configuration for the image is complete")
	}
}

// buildInstallerArgs returns the arguments for the Falcon sensor installer based on the OS.
func (fi FalconInstaller) buildInstallerArgs() []string {
	// Start with OS-specific base arguments
	args := fi.getBaseInstallerArgs()

	// Add common configuration arguments
	args = fi.addCommonConfigArgs(args)

	// Add proxy configuration arguments
	args = fi.addProxyConfigArgs(args)

	return args
}

// getBaseInstallerArgs returns the base arguments specific to each OS.
func (fi FalconInstaller) getBaseInstallerArgs() []string {
	switch fi.OSType {
	case "linux":
		return []string{"-sf"}
	case "windows":
		args := []string{"/install", "/quiet"}

		// Add Windows-specific options
		if !fi.SensorConfig.Restart {
			args = append(args, "/norestart")
		}

		if fi.SensorConfig.ProvisioningWaitTime != 0 {
			args = append(args, fmt.Sprintf("ProvWaitTime=%d", fi.SensorConfig.ProvisioningWaitTime))
		}

		if fi.SensorConfig.DisableProvisioningWait {
			args = append(args, "ProvNoWait=1")
		}

		if fi.SensorConfig.NoStart {
			args = append(args, "NoStart=1")
		}

		if fi.SensorConfig.VDI {
			args = append(args, "VDI=1")
		}

		if fi.SensorConfig.PACURL != "" {
			args = append(args, fmt.Sprintf("PACURL=%s", fi.SensorConfig.PACURL))
		}

		return args
	default:
		return []string{}
	}
}

// addCommonConfigArgs adds configuration arguments common to all platforms.
func (fi FalconInstaller) addCommonConfigArgs(args []string) []string {
	// Add CID if provided
	if fi.SensorConfig.CID != "" {
		args = append(args, fi.formatArg("cid", fi.SensorConfig.CID))
	}

	// Add provisioning token if provided
	if fi.SensorConfig.ProvisioningToken != "" {
		args = append(args, fi.formatArg("provisioning-token", fi.SensorConfig.ProvisioningToken))
	}

	// Add tags if provided
	if fi.SensorConfig.Tags != "" {
		args = append(args, fi.formatArg("tags", fi.SensorConfig.Tags))
	}

	return args
}

// addProxyConfigArgs adds proxy configuration arguments.
func (fi FalconInstaller) addProxyConfigArgs(args []string) []string {
	// Handle proxy disable flag
	// Handle proxy disable differently per OS
	if fi.SensorConfig.ProxyDisable {
		switch fi.OSType {
		case "windows":
			args = append(args, fi.formatArg("apd", "1"))
		case "linux":
			args = append(args, fi.formatArg("apd", "true"))
		}
	} else {
		// Add proxy host if provided
		if fi.SensorConfig.ProxyHost != "" {
			args = append(args, fi.formatArg("aph", fi.SensorConfig.ProxyHost))
		}

		// Add proxy port if provided
		if fi.SensorConfig.ProxyPort != "" {
			args = append(args, fi.formatArg("app", fi.SensorConfig.ProxyPort))
		}
	}

	return args
}

// formatArg formats an argument based on the OS.
func (fi FalconInstaller) formatArg(arg, val string) string {
	switch fi.OSType {
	case "windows":
		return fmt.Sprintf("%s=%s", windowsFalconArgMap[arg], val)
	default:
		return fmt.Sprintf("--%s=%s", arg, val)
	}
}

// buildMacOSArgs builds arguments for macOS-specific commands.
func (fi FalconInstaller) buildMacOSArgs(command string) []string {
	var args []string
	requiresMaintenanceToken := false

	switch command {
	case "load":
		args = []string{"load"}
	case "unload":
		args = []string{"unload"}
		requiresMaintenanceToken = true
	case "uninstall":
		args = []string{"uninstall"}
		requiresMaintenanceToken = true
	case "license":
		args = []string{"license", fi.SensorConfig.CID}
		if fi.SensorConfig.ProvisioningToken != "" {
			args = append(args, fi.SensorConfig.ProvisioningToken)
		}
	case "grouping-tags":
		args = []string{"grouping-tags", "set", fi.SensorConfig.Tags}
		requiresMaintenanceToken = true
	}

	// Add maintenance token flag if needed and available
	if fi.SensorConfig.MaintenanceToken != "" && requiresMaintenanceToken {
		args = append(args, "--maintenance-token")
	}

	return args
}

// installSensor installs the Falcon sensor using the appropriate method for the OS.
func (fi FalconInstaller) installSensor(path string) error {
	slog.Debug("Starting Falcon sensor installation", "osType", fi.OSType, "path", path)

	switch fi.OSType {
	case "linux":
		return fi.installLinuxSensor(path)
	case "windows":
		return fi.installWindowsSensor(path)
	case "macos", "darwin":
		return fi.installMacOSSensor(path)
	default:
		return fmt.Errorf("unsupported OS for installation: %s", fi.OSType)
	}
}

// installLinuxSensor installs the Falcon sensor on Linux systems.
func (fi FalconInstaller) installLinuxSensor(path string) error {
	// Define package managers in order of preference
	packageManagers := []struct {
		path    string
		args    []string
		envVars []string
	}{
		{"/usr/bin/dnf", []string{"install", "-q", "-y", path}, nil},
		{"/usr/bin/yum", []string{"install", "-q", "-y", path}, nil},
		{"/usr/bin/zypper", []string{"install", "--quiet", "-y", path}, nil},
		{"/usr/bin/apt-get", []string{"install", "-y", path}, []string{"DEBIAN_FRONTEND=noninteractive"}},
		{"/usr/bin/dpkg", []string{"install", "--qq", "-y", path}, []string{"DEBIAN_FRONTEND=noninteractive"}},
	}

	// Find the first available package manager
	for _, pm := range packageManagers {
		if cmd, err := exec.LookPath(pm.path); err == nil {
			slog.Debug("Using package manager for installation",
				"command", cmd, "args", pm.args, "env", pm.envVars)

			stdout, stderr, err := installSensorWithRetry(cmd, pm.envVars, pm.args)
			if err != nil {
				return fmt.Errorf("failed to install sensor: %w (stdout: %s, stderr: %s)",
					err, stdout, stderr)
			}

			slog.Debug("Successfully installed Falcon sensor",
				"stdout", string(stdout), "stderr", string(stderr))
			return nil
		}
	}

	return fmt.Errorf("no supported package manager found for installation")
}

// installWindowsSensor installs the Falcon sensor on Windows systems.
func (fi FalconInstaller) installWindowsSensor(path string) error {
	falconArgs := fi.buildInstallerArgs()
	slog.Debug("Installing Falcon sensor on Windows", "installer", path, "args", falconArgs)

	stdout, stderr, err := utils.RunCmd(path, falconArgs)
	if err != nil {
		return fmt.Errorf("failed to install sensor: %w (stdout: %s, stderr: %s)",
			err, string(stdout), string(stderr))
	}

	return nil
}

// installMacOSSensor installs the Falcon sensor on macOS systems.
func (fi FalconInstaller) installMacOSSensor(path string) error {
	const installerPath = "/usr/sbin/installer"
	args := []string{"-verboseR", "-pkg", path, "-target", "/"}

	slog.Debug("Installing Falcon sensor on macOS",
		"command", installerPath, "args", args)

	stdout, stderr, err := utils.RunCmd(installerPath, args)
	if err != nil {
		return fmt.Errorf("failed to install sensor: %w (stdout: %s, stderr: %s)",
			err, string(stdout), string(stderr))
	}

	return nil
}

// installSensorWithRetry attempts to install the sensor every 5 seconds for 10 minutes.
func installSensorWithRetry(c string, env []string, args []string) ([]byte, []byte, error) {
	const maxRetries = 120
	const retryInterval = 5 * time.Second

	for i := 0; i < maxRetries; i++ {
		lock, err := osutils.PackageManagerLock()
		if err != nil {
			return nil, nil, fmt.Errorf("Error checking package manager lock: %v", err)
		}

		if !lock {
			stdout, stderr, err := utils.RunCmd(c, args, utils.WithCmdEnvOption(env))
			if err != nil {
				return stdout, stderr, err
			}

			return stdout, stderr, nil
		}

		slog.Warn("Package lock detected. Waiting before retrying sensor installation", "Attempt", i+1, "RetryInterval", retryInterval)
		time.Sleep(retryInterval)
	}

	return []byte("nil"), []byte("Could not install the sensor"), fmt.Errorf("Exceeded maximum retries: %d", maxRetries)
}

// rpmGpgKeyRetryImport attempts to import the GPG key every 5 seconds for 10 minutes.
func rpmGpgKeyRetryImport(gpgKey string) error {
	const maxRetries = 120
	const retryInterval = 5 * time.Second

	for i := 0; i < maxRetries; i++ {
		lock, err := osutils.PackageManagerLock()
		if err != nil {
			return fmt.Errorf("Error checking package manager lock: %v", err)
		}

		if !lock {
			err = rpm.GpgKeyImport(gpgKey)
			if err != nil {
				log.Fatalf("Error importing GPG key: %v", err)
			}

			return nil
		}

		slog.Warn("Package lock detected. Waiting before retrying to import GPG Key", "Attempt", i+1, "RetryInterval", retryInterval)
		time.Sleep(retryInterval)
	}

	return fmt.Errorf("Could not install the GPG Key. Exceeded maximum retries: %d", maxRetries)
}

// configureSensorImage configures the Falcon sensor on the image.
func (fi FalconInstaller) configureSensorImage() error {
	switch fi.OSType {
	case "linux":
		var err error
		const maxRetries = 24
		const retryInterval = 5 * time.Second
		aid := []string{"-g", "--aid"}
		val := ""

		for i := 0; i < maxRetries; i++ {
			if val, err = falconctl.Get(aid); err != nil {
				return fmt.Errorf("Error retrieving Falcon sensor settings: %v", err)
			}

			if strings.Contains(val, "aid is not set.") {
				slog.Warn("Sensor has not return an AID yet. Retrying...", "Attempt", i+1, "RetryInterval", retryInterval)
				time.Sleep(retryInterval)
			} else {
				break
			}

			if i == maxRetries-1 {
				return fmt.Errorf("Sensor has not returned an AID")
			}
		}

		// Remove the aid
		slog.Debug("Removing the aid from the sensor configuration")
		delAid := []string{"-d", "-f", "--aid"}
		if err := falconctl.Set(delAid); err != nil {
			return fmt.Errorf("Error configuring Falcon sensor: %v", err)
		}

		// re-add the provisioning token if it was used
		if fi.SensorConfig.ProvisioningToken != "" {
			slog.Debug("Re-adding provisioning token")
			token := []string{"-s", "-f", fmt.Sprintf("--provisioning-token=%s", fi.SensorConfig.ProvisioningToken)}
			if err := falconctl.Set(token); err != nil {
				return fmt.Errorf("Error configuring Falcon sensor: %v", err)
			}
		}
	case "macos":
		registryBase := "/Library/Application Support/CrowdStrike/Falcon/registry.base"

		slog.Debug("Unloading Falcon sensor")
		if err := falconctl.Set(fi.buildMacOSArgs("unload")); err != nil {
			return fmt.Errorf("Error unloading Falcon sensor: %v", err)
		}

		slog.Debug("Removing registry.base", "Path", registryBase)
		err := os.Remove(registryBase)
		if err != nil {
			log.Fatalf("Error removing registry.base: %v", err)
		}
	}

	return nil
}
