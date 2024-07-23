package installer

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/exec"
	"slices"
	"strings"

	"github.com/crowdstrike/falcon-installer/pkg/rpm"
	"github.com/crowdstrike/falcon-installer/pkg/systemd"
	"github.com/crowdstrike/falcon-installer/pkg/utils"
	"github.com/crowdstrike/falcon-installer/pkg/utils/osutils"
	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/sensor_download"
	"github.com/crowdstrike/gofalcon/falcon/client/sensor_update_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
)

const falconInstallDir = "/opt/CrowdStrike"

var (
	enterpriseLinux = []string{"rhel", "centos", "oracle", "almalinux", "rocky"}
)

type FalconSensorCLI struct {
	CID               string
	APD               string
	APH               string
	APP               string
	Tags              string
	ProvisioningToken string
}

type FalconInstaller struct {
	ClientId               string
	ClientSecret           string
	MemberCID              string
	Cloud                  string
	SensorUpdatePolicyName string
	TmpDir                 string
	Arch                   string
	OS                     string
	OsName                 string
	OsVersion              string
	GpgKeyFile             string
	UserAgent              string

	SensorConfig FalconSensorCLI
}

func Run(fc FalconInstaller) {
	falconInstalled, err := osutils.FalconInstalled(fc.OS)
	if err != nil {
		log.Fatalf("Error checking if Falcon sensor is installed: %v", err)
	}

	client, err := falcon.NewClient(&falcon.ApiConfig{
		ClientId:          fc.ClientId,
		ClientSecret:      fc.ClientSecret,
		MemberCID:         fc.MemberCID,
		Cloud:             falcon.Cloud(fc.Cloud),
		Context:           context.Background(),
		UserAgentOverride: fc.UserAgent,
	})
	if err != nil {
		log.Fatalf("Error creating Falcon client: %v", err)
	}

	falconArgs := fc.falconArgs()

	if !falconInstalled {
		if rpm.IsRpmInstalled() {
			slog.Info("Installing CrowdStrike Falcon GPG key")
			if fc.GpgKeyFile != "" {
				slog.Debug("Using provided GPG key", "GPG Key", fc.GpgKeyFile)
				err = rpm.GpgKeyImport(fc.GpgKeyFile)
				if err != nil {
					log.Fatalf("Error importing GPG key: %v", err)
				}
			} else {
				gpgKeyFile := fmt.Sprintf("%s%s%s", fc.TmpDir, string(os.PathSeparator), "falcon-gpg-key")
				err = os.WriteFile(gpgKeyFile, []byte(gpgPublicKey), 0600)
				if err != nil {
					log.Fatalf("Error writing GPG key to file: %v", err)
				}
				slog.Debug("Using embedded GPG key", "GPG Key", gpgKeyFile, "Key", gpgPublicKey)
				if err = rpm.GpgKeyImport(gpgKeyFile); err != nil {
					log.Fatalf("Error importing GPG key: %v", err)
				}
			}

		}

		if fc.SensorConfig.CID == "" {
			fc.SensorConfig.CID, err = fc.getCID(context.Background(), client)
			if err != nil {
				log.Fatalf("Error getting Falcon CID: %v", err)
			}
			slog.Debug("Found suitable Falcon Customer ID (CID)", "CID", fc.SensorConfig.CID)
			falconArgs = append(falconArgs, fc.osArgHandler("cid", fc.SensorConfig.CID))
		}

		sensor := fc.querySuitableSensor(client, "latest")
		if sensor == nil {
			log.Fatalf("Could not find Falcon sensor for '%s' '%s'", fc.OsName, fc.OsVersion)
		}

		path := fc.download(client, sensor, fc.TmpDir, *sensor.Name)

		slog.Info("Starting Falcon sensor installation")
		fc.installSensor(path)
	} else {
		slog.Info("Sensor is already installed. Skipping download and installation")
	}

	if fc.OS == "linux" {
		if len(falconArgs) > 1 {
			if err := configureLinuxSensor(falconArgs); err != nil {
				log.Fatalf("Error configuring Falcon sensor: %v", err)
			}
		} else {
			slog.Info("Skipping Falcon sensor configuration. No additional configuration required")
		}

		// Restart Falcon sensor service if it was installed
		if !falconInstalled {
			if fc.OsName == "ubuntu" && fc.OsVersion == "14" {
				if _, _, err := utils.RunCmd("service", []string{"falcon-sensor", "restart"}); err != nil {
					log.Fatalf("Error restarting Falcon sensor service: %v", err)
				}
			} else {
				if err := systemd.RestartService("falcon-sensor"); err != nil {
					log.Fatalf("Error restarting Falcon sensor service: %v", err)
				}
			}
		}
	}

	slog.Info("Falcon sensor installation complete")
}

// falconArgs returns the arguments for the Falcon sensor installer based on the OS
func (fi FalconInstaller) falconArgs() []string {
	falconArgs := []string{}

	switch fi.OS {
	case "linux":
		falconArgs = []string{"-sf"}
	case "windows":
		falconArgs = []string{"/install", "/quiet"}
	}

	if fi.SensorConfig.CID != "" {
		falconArgs = append(falconArgs, fi.osArgHandler("cid", fi.SensorConfig.CID))
	}
	if fi.SensorConfig.ProvisioningToken != "" {
		falconArgs = append(falconArgs, fi.osArgHandler("provisioning-token", fi.SensorConfig.ProvisioningToken))
	}
	if fi.SensorConfig.Tags != "" {
		falconArgs = append(falconArgs, fi.osArgHandler("tags", fi.SensorConfig.Tags))
	}
	if fi.SensorConfig.APD != "" {
		falconArgs = append(falconArgs, fi.osArgHandler("apd", fi.SensorConfig.APD))
	}
	if fi.SensorConfig.APH != "" {
		falconArgs = append(falconArgs, fi.osArgHandler("aph", fi.SensorConfig.APH))
	}
	if fi.SensorConfig.APP != "" {
		falconArgs = append(falconArgs, fi.osArgHandler("app", fi.SensorConfig.APP))
	}

	return falconArgs
}

// osArgHandler handles the formatting of arguments for the Falcon sensor installer based on the OS
func (fi FalconInstaller) osArgHandler(arg, val string) string {
	windowsFalconMap := map[string]string{
		"cid":                "CID",
		"provisioning-token": "ProvToken",
		"tags":               "GROUPING_TAGS",
		"apd":                "PROXYDISABLE",
		"aph":                "APP_PROXYNAME",
		"app":                "APP_PROXYPORT",
	}

	switch fi.OS {
	case "windows":
		return fmt.Sprintf("%s=%s", windowsFalconMap[arg], val)
	default:
		return fmt.Sprintf("--%s=%s", arg, val)
	}
}

// getSensorUpdatePolicies queries the CrowdStrike API for sensor update policies that match the provided policy name and architecture
func (fi FalconInstaller) getSensorUpdatePolicies(client *client.CrowdStrikeAPISpecification) string {
	var filter *string
	csPlatformName := ""

	switch fi.OS {
	case "windows":
		csPlatformName = "windows"
	default:
		csPlatformName = "Linux"
	}

	f := fmt.Sprintf("platform_name:~\"%s\"+name.raw:\"%s\"", csPlatformName, fi.SensorUpdatePolicyName)
	slog.Debug("Sensor Update Policy Query", slog.String("Filter", f))
	filter = &f

	res, err := client.SensorUpdatePolicies.QueryCombinedSensorUpdatePoliciesV2(
		&sensor_update_policies.QueryCombinedSensorUpdatePoliciesV2Params{
			Filter:  filter,
			Context: context.Background(),
		},
	)
	if err != nil {
		log.Fatal(falcon.ErrorExplain(err))
	}
	payload := res.GetPayload()
	if err = falcon.AssertNoError(payload.Errors); err != nil {
		log.Fatal(err)
	}

	senserVersion := ""
	for _, policy := range payload.Resources {
		if *policy.Enabled && *policy.Settings.Stage == "prod" {
			switch fi.OS {
			case "linux":
				switch fi.Arch {
				case "arm64":
					for _, variant := range policy.Settings.Variants {
						if strings.Contains(strings.ToLower(*variant.Platform), "arm64") {
							senserVersion = *variant.SensorVersion
							slog.Debug("arm64 sensor update policy versions", "Version", senserVersion)
						}
					}
				case "s390x":
					for _, variant := range policy.Settings.Variants {
						if strings.Contains(strings.ToLower(*variant.Platform), "zlinux") {
							senserVersion = *variant.SensorVersion
							slog.Debug("zLinux sensor update policy version", "Version", senserVersion)
						}
					}
				default:
					senserVersion = *policy.Settings.SensorVersion
				}
			default:
				senserVersion = *policy.Settings.SensorVersion
			}
		}
	}

	slog.Debug("Found suitable Falcon sensor version from sensor update policies", "Version", senserVersion)
	return senserVersion
}

// getSensors queries the CrowdStrike API for Falcon sensors that match the provided OS name, version, and architecture
func (fi FalconInstaller) getSensors(client *client.CrowdStrikeAPISpecification) []*models.DomainSensorInstallerV2 {
	var filter *string

	// If the OS name is in the enterpriseLinux list, replace it with a wildcard
	osName := fi.OsName

	sensorVersion := fi.getSensorUpdatePolicies(client)
	if osName != "" {
		if slices.Contains(enterpriseLinux, strings.ToLower(osName)) {
			slog.Debug("Adding wildcard for Enterprise Linux", "Distros", enterpriseLinux, "OS", osName, "Version", fi.OsVersion)
			osName = "*RHEL*"
		}

		f := fmt.Sprintf("os:~\"%s\"+os_version:\"*%s*\"+architectures:\"%s\"", osName, fi.OsVersion, fi.Arch)
		if sensorVersion != "" {
			f = fmt.Sprintf("%s+version:\"%s\"", f, sensorVersion)
		}
		slog.Debug("Sensor Installer Query", slog.String("Filter", f))
		filter = &f
	}

	res, err := client.SensorDownload.GetCombinedSensorInstallersByQueryV2(
		&sensor_download.GetCombinedSensorInstallersByQueryV2Params{
			Context: context.Background(),
			Filter:  filter,
		},
	)
	if err != nil {
		log.Fatal(falcon.ErrorExplain(err))
	}
	payload := res.GetPayload()
	if err = falcon.AssertNoError(payload.Errors); err != nil {
		log.Fatal(err)
	}

	k := 0
	for _, sensor := range payload.Resources {
		slog.Debug(*sensor.Description)
		if strings.Contains(*sensor.Description, "Falcon SIEM Connector") {
			continue
		}
		payload.Resources[k] = sensor
		k++
	}

	return payload.Resources[:k]
}

// querySuitableSensor queries the CrowdStrike API for a suitable Falcon sensor that matches the provided OS name, version, and architecture
func (fi FalconInstaller) querySuitableSensor(client *client.CrowdStrikeAPISpecification, sensorVersion string) *models.DomainSensorInstallerV2 {
	for _, sensor := range fi.getSensors(client) {
		if strings.Contains(*sensor.OsVersion, fi.OsVersion) {
			if *sensor.Version == sensorVersion || sensorVersion == "latest" {
				slog.Debug("Found suitable Falcon sensor", "Version", *sensor.Version)
				return sensor
			}
		}
	}
	return nil
}

// getCID gets the Falcon CID from the CrowdStrike API using the SensorDownload API
func (fi FalconInstaller) getCID(ctx context.Context, client *client.CrowdStrikeAPISpecification) (string, error) {
	response, err := client.SensorDownload.GetSensorInstallersCCIDByQuery(&sensor_download.GetSensorInstallersCCIDByQueryParams{
		Context: ctx,
	})
	if err != nil {
		return "", fmt.Errorf("Could not get Falcon CID from CrowdStrike Falcon API: %v", err)
	}
	payload := response.GetPayload()
	if err = falcon.AssertNoError(payload.Errors); err != nil {
		return "", fmt.Errorf("Error reported when getting Falcon CID from CrowdStrike Falcon API: %v", err)
	}
	if len(payload.Resources) != 1 {
		return "", fmt.Errorf("Failed to get Falcon CID: Unexpected API response: %v", payload.Resources)
	}
	return payload.Resources[0], nil

}

// download downloads the Falcon sensor installer using the CrowdStrike API and saves it to the provided directory
func (fi FalconInstaller) download(client *client.CrowdStrikeAPISpecification, sensor *models.DomainSensorInstallerV2, dir, filename string) string {
	file, err := utils.OpenFileForWriting(dir, filename)
	if err != nil {
		log.Fatal(err)
	}

	_, err = client.SensorDownload.DownloadSensorInstallerByIDV2(
		&sensor_download.DownloadSensorInstallerByIDV2Params{
			Context: context.Background(),
			ID:      *sensor.Sha256,
		}, file)
	if err != nil {
		log.Fatal(falcon.ErrorExplain(err))
	}

	if err := file.Close(); err != nil {
		log.Fatal(err)
	}

	fullPath := fmt.Sprintf("%s%s%s", dir, string(os.PathSeparator), filename)
	slog.Debug(fmt.Sprintf("Downloaded %s to %s", *sensor.Description, fullPath))
	return fullPath
}

// installSensor installs the Falcon sensor using the appropriate package manager
func (fi FalconInstaller) installSensor(path string) {
	c := ""
	env := ""
	args := []string{}

	switch fi.OS {
	case "linux":
		if cmd, err := exec.LookPath("/usr/bin/dnf"); err == nil {
			c = cmd
			args = []string{"install", "-q", "-y", path}
		} else if cmd, err := exec.LookPath("/usr/bin/yum"); err == nil {
			c = cmd
			args = []string{"install", "-q", "-y", path}
		} else if cmd, err := exec.LookPath("/usr/bin/zypper"); err == nil {
			c = cmd
			args = []string{"install", "--quiet", "-y", path}
		} else if cmd, err := exec.LookPath("/usr/bin/apt-get"); err == nil {
			c = cmd

			if fi.OsVersion != "14" {
				args = []string{"install", "-y", path}
				env = "DEBIAN_FRONTEND=noninteractive"
			} else {
				args = []string{"-i", path}
				env = "DEBIAN_FRONTEND=noninteractive"
				c = "/usr/bin/dpkg"
			}
		} else if cmd, err := exec.LookPath("/usr/bin/dpkg"); err == nil {
			c = cmd
			args = []string{"install", "--qq", "-y", path}
			env = "DEBIAN_FRONTEND=noninteractive"
		} else {
			log.Fatalf("Unable to find expected linux package manager. Unsupported package manager: %v", err)
		}

		stdout, stderr, err := utils.RunCmdWithEnv(c, env, args)
		if err != nil {
			log.Fatalf("Error running %s: %v, %s", c, err, string(stderr))
		}

		slog.Debug("Installing Falcon Sensor", string(stdout), string(stderr))

		// Remove when we no longer support Ubuntu 14
		if fi.OsVersion == "14" {
			args = []string{"-qq", "install", "-f", "-y"}
			env = "DEBIAN_FRONTEND=noninteractive"

			_, stderr, err := utils.RunCmdWithEnv("/usr/bin/apt-get", env, args)
			if err != nil {
				log.Fatalf("Error running dpkg: %v, %s", err, string(stderr))
			}

			slog.Debug("Installing dependencies for Ubuntu 14.04", string(stdout), string(stderr))
		}

	case "windows":
		stdout, stderr, err := utils.RunCmd(path, args)
		if err != nil {
			log.Fatalf("Error running %s: %v, %s", path, err, string(stderr))
		}

		slog.Debug("Installing Falcon Sensor", string(stdout), string(stderr))
	}
}

// configureLinuxSensor configures the Falcon sensor on Linux using falconctl command
func configureLinuxSensor(args []string) error {
	falconCtlCmd := fmt.Sprintf("%s%sfalconctl", falconInstallDir, string(os.PathSeparator))
	slog.Debug("Configuring Falcon sensor", "Command", falconCtlCmd, "Args", args)

	if _, err := exec.LookPath(falconCtlCmd); err != nil {
		return fmt.Errorf("Could not find falconctl: %s: %v", falconCtlCmd, err)
	}

	if _, stderr, err := utils.RunCmd(falconCtlCmd, args); err != nil {
		return fmt.Errorf("Error running falconctl: %v, stderr: %s", err, string(stderr))
	}

	return nil
}
