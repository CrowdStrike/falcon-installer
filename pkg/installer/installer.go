package installer

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/crowdstrike/falcon-installer/pkg/rpm"
	"github.com/crowdstrike/falcon-installer/pkg/systemd"
	"github.com/crowdstrike/falcon-installer/pkg/utils"
	"github.com/crowdstrike/falcon-installer/pkg/utils/osutils"
	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/installation_tokens"
	"github.com/crowdstrike/gofalcon/falcon/client/sensor_download"
	"github.com/crowdstrike/gofalcon/falcon/client/sensor_update_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
)

const falconLinuxInstallDir = "/opt/CrowdStrike"

var (
	enterpriseLinux     = []string{"rhel", "centos", "oracle", "almalinux", "rocky"}
	windowsFalconArgMap = map[string]string{
		"cid":                "CID",
		"provisioning-token": "ProvToken",
		"tags":               "GROUPING_TAGS",
		"apd":                "PROXYDISABLE",
		"aph":                "APP_PROXYNAME",
		"app":                "APP_PROXYPORT",
	}
)

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
	// ProvisioningToken is the token used to provision the sensor. If not provided, the API will attempt to retrieve a token.
	ProvisioningToken string
	// DisableProvisioningWait allows the Windows installer more provisioning time when communicating with CrowdStrike. Windows only.
	DisableProvisioningWait bool
	// ProvisioningWaitTime is the time in milliseconds to wait for the sensor to provision. Windows only.
	ProvisioningWaitTime uint64
	// PACURL is the proxy auto-config URL for the sensor to use when communicating with CrowdStrike.
	PACURL string
	// Restart will allow the system to restart if necessary after sensor installation. Windows only.
	Restart bool
}

type FalconInstaller struct {
	// ClientId is the client ID for accessing CrowdStrike Falcon Platform.
	ClientId string
	// ClientSecret is the client secret for accessing CrowdStrike Falcon Platform.
	ClientSecret string
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
	// OS is the operating system to install the sensor on.
	OS string
	// OsName is the name of the OS to use when querying for the sensor.
	OsName string
	// OsVersion is the version of the OS to use when querying for the sensor.
	OsVersion string
	// GpgKeyFile is the path to the GPG key file to use for importing the key. Linux only.
	GpgKeyFile string
	// UserAgent is the user agent string to use when making API requests.
	UserAgent string

	// SensorConfig is the configuration for the Falcon sensor CLI args.
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

	// Get the provisioning token from the API if not provided
	if fc.SensorConfig.ProvisioningToken == "" {
		fc.SensorConfig.ProvisioningToken = fc.getSensorProvisioningToken(client)
		if fc.SensorConfig.ProvisioningToken != "" {
			falconArgs = append(falconArgs, fc.osArgHandler("provisioning-token", fc.SensorConfig.ProvisioningToken))
		}
	}

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

		// Get the Falcon CID from the API if not provided
		if fc.SensorConfig.CID == "" {
			fc.SensorConfig.CID, err = fc.getCID(context.Background(), client)
			if err != nil {
				log.Fatalf("Error getting Falcon CID: %v", err)
			}
			slog.Debug("Found suitable Falcon Customer ID (CID)", "CID", fc.SensorConfig.CID)
			falconArgs = append(falconArgs, fc.osArgHandler("cid", fc.SensorConfig.CID))
		}

		// Query the CrowdStrike API for a suitable Falcon sensor
		sensor := fc.querySuitableSensor(client, "latest")
		if sensor == nil {
			log.Fatalf("Could not find Falcon sensor for '%s' '%s'", fc.OsName, fc.OsVersion)
		}

		// Download the Falcon sensor installer from the CrowdStrike API
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
			if err := systemd.RestartService("falcon-sensor"); err != nil {
				log.Fatalf("Error restarting Falcon sensor service: %v", err)
			}
		}
	}

	slog.Info("Falcon sensor installation complete")
}

// falconArgs returns the arguments for the Falcon sensor installer based on the OS.
func (fi FalconInstaller) falconArgs() []string {
	falconArgs := []string{}

	switch fi.OS {
	case "linux":
		falconArgs = []string{"-sf"}
	case "windows":
		falconArgs = []string{"/install", "/quiet"}

		if !fi.SensorConfig.Restart {
			falconArgs = append(falconArgs, "/norestart")
		}

		if fi.SensorConfig.ProvisioningWaitTime != 0 {
			falconArgs = append(falconArgs, fmt.Sprintf("ProvWaitTime=%d", fi.SensorConfig.ProvisioningWaitTime))
		}

		if fi.SensorConfig.DisableProvisioningWait {
			falconArgs = append(falconArgs, "ProvNoWait=1")
		}

		if fi.SensorConfig.PACURL != "" {
			falconArgs = append(falconArgs, fmt.Sprintf("PACURL=%s", fi.SensorConfig.PACURL))
		}
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

	if fi.SensorConfig.ProxyDisable || fi.SensorConfig.ProxyHost != "" || fi.SensorConfig.ProxyPort != "" {
		// apd = "true" for Linux, PROXYDISABLE=1 for Windows, default is empty to use the sensor's default setting.
		// For Windows, PROXYDISABLE=0 is not needed because the default is to have the proxy enabled.
		// For Linux, the default is to have the proxy unset.
		val := ""

		switch fi.OS {
		case "windows":
			// Windows default is to have the proxy enabled.
			if fi.SensorConfig.ProxyDisable {
				val = fmt.Sprintf("%d", utils.BoolToInt(fi.SensorConfig.ProxyDisable))
			}
		case "linux":
			val = strconv.FormatBool(fi.SensorConfig.ProxyDisable)
		}

		if val != "" {
			falconArgs = append(falconArgs, fi.osArgHandler("apd", val))
		}
	}

	if fi.SensorConfig.ProxyHost != "" {
		falconArgs = append(falconArgs, fi.osArgHandler("aph", fi.SensorConfig.ProxyHost))
	}

	if fi.SensorConfig.ProxyPort != "" {
		falconArgs = append(falconArgs, fi.osArgHandler("app", fi.SensorConfig.ProxyPort))
	}

	return falconArgs
}

// osArgHandler handles the formatting of arguments for the Falcon sensor installer based on the OS.
func (fi FalconInstaller) osArgHandler(arg, val string) string {
	switch fi.OS {
	case "windows":
		return fmt.Sprintf("%s=%s", windowsFalconArgMap[arg], val)
	default:
		return fmt.Sprintf("--%s=%s", arg, val)
	}
}

// getSensorProvisioningToken queries the CrowdStrike API for the sensor provisioning token.
func (fi FalconInstaller) getSensorProvisioningToken(client *client.CrowdStrikeAPISpecification) string {
	res, err := client.InstallationTokens.CustomerSettingsRead(
		&installation_tokens.CustomerSettingsReadParams{
			Context: context.Background(),
		},
	)
	if err != nil {
		errPayload := falcon.ErrorExtractPayload(err)
		if errPayload == nil {
			log.Fatal(falcon.ErrorExplain(err))
		}

		bytes, err := errPayload.MarshalBinary()
		if err != nil {
			log.Fatal(err)
		}

		if strings.Contains(string(bytes), "\"code\":403,\"message\":\"access denied, authorization failed\"") {
			slog.Warn("Skipping getting installation tokens because the OAuth scope does not have permission to read installation tokens. If you are using provisioning tokens, please provide the token via CLI or update the OAuth2 client with the `Installation Tokens: Read` scope.")
			return ""
		} else {
			log.Fatal(falcon.ErrorExplain(err))
		}
	}

	payload := res.GetPayload()
	if err = falcon.AssertNoError(payload.Errors); err != nil {
		log.Fatal(err)
	}

	token := ""
	if payload.Resources[0].TokensRequired != nil && *payload.Resources[0].TokensRequired {
		token = fi.getToken(client, fi.getTokenList(client))
		slog.Debug("Found suitable Falcon installation token", "Token", token)
	}

	return token
}

// getTokenList queries the CrowdStrike API for the installation tokens.
func (fi FalconInstaller) getTokenList(client *client.CrowdStrikeAPISpecification) []string {
	res, err := client.InstallationTokens.TokensQuery(
		&installation_tokens.TokensQueryParams{
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

	return payload.Resources
}

// getToken queries the CrowdStrike API for the installation token using the token ID.
func (fi FalconInstaller) getToken(client *client.CrowdStrikeAPISpecification, tokenList []string) string {
	res, err := client.InstallationTokens.TokensRead(
		&installation_tokens.TokensReadParams{
			Context: context.Background(),
			Ids:     tokenList,
		},
	)
	if err != nil {
		log.Fatal(falcon.ErrorExplain(err))
	}

	payload := res.GetPayload()
	if err = falcon.AssertNoError(payload.Errors); err != nil {
		log.Fatal(err)
	}

	return *payload.Resources[0].Value
}

// getSensorUpdatePolicies queries the CrowdStrike API for sensor update policies that match the provided policy name and architecture.
func (fi FalconInstaller) getSensorUpdatePolicies(client *client.CrowdStrikeAPISpecification) string {
	var filter *string
	csPlatformName := ""

	switch fi.OS {
	case "windows":
		csPlatformName = "windows"
	default:
		csPlatformName = "Linux"
	}

	// Set default sensor update policy name if not provided
	if fi.SensorUpdatePolicyName == "" {
		fi.SensorUpdatePolicyName = "platform_default"
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

	sensorVersion := ""
	for _, policy := range payload.Resources {
		if *policy.Enabled && *policy.Settings.Stage == "prod" {
			switch fi.OS {
			case "linux":
				switch fi.Arch {
				case "arm64":
					for _, variant := range policy.Settings.Variants {
						if strings.Contains(strings.ToLower(*variant.Platform), "arm64") {
							sensorVersion = *variant.SensorVersion
							slog.Debug("arm64 sensor update policy versions", "Version", sensorVersion)
						}
					}
				case "s390x":
					for _, variant := range policy.Settings.Variants {
						if strings.Contains(strings.ToLower(*variant.Platform), "zlinux") {
							sensorVersion = *variant.SensorVersion
							slog.Debug("zLinux sensor update policy version", "Version", sensorVersion)
						}
					}
				default:
					sensorVersion = *policy.Settings.SensorVersion
				}
			default:
				sensorVersion = *policy.Settings.SensorVersion
			}
		}
	}

	slog.Debug("Found suitable Falcon sensor version from sensor update policies", "Version", sensorVersion)
	return sensorVersion
}

// getSensors queries the CrowdStrike API for Falcon sensors that match the provided OS name, version, and architecture.
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

// querySuitableSensor queries the CrowdStrike API for a suitable Falcon sensor that matches the provided OS name, version, and architecture.
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

// getCID gets the Falcon CID from the CrowdStrike API using the SensorDownload API.
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

// download downloads the Falcon sensor installer using the CrowdStrike API and saves it to the provided directory.
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

// installSensor installs the Falcon sensor using the appropriate package manager.
func (fi FalconInstaller) installSensor(path string) {
	c := ""
	env := ""
	args := []string{} //nolint:staticcheck

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
			args = []string{"install", "-y", path}
			env = "DEBIAN_FRONTEND=noninteractive"
		} else if cmd, err := exec.LookPath("/usr/bin/dpkg"); err == nil {
			c = cmd
			args = []string{"install", "--qq", "-y", path}
			env = "DEBIAN_FRONTEND=noninteractive"
		} else {
			log.Fatalf("Unable to find expected linux package manager. Unsupported package manager: %v", err)
		}

		stdout, stderr, err := installSensorWithRetry(c, env, args)
		if err != nil {
			log.Fatalf("Error running %s: %v, stdout: %s, stderr: %s", c, err, string(stdout), string(stderr))
		}

		slog.Debug("Installing Falcon Sensor", string(stdout), string(stderr))
	case "windows":
		stdout, stderr, err := utils.RunCmd(path, fi.falconArgs())
		if err != nil {
			log.Fatalf("Error running %s: %v, stdout: %s, stderr: %s", path, err, string(stdout), string(stderr))
		}

		slog.Debug("Installing Falcon Sensor")
	}
}

// installSensorWithRetry attempts to install the sensor every 5 seconds for 2 minutes.
func installSensorWithRetry(c string, env string, args []string) ([]byte, []byte, error) {
	const maxRetries = 24
	const retryInterval = 5 * time.Second

	for i := 0; i < maxRetries; i++ {
		stdout, stderr, err := utils.RunCmdWithEnv(c, env, args)
		if err == nil {
			return stdout, stderr, nil
		}

		if strings.Contains(string(stderr), "E: Could not get lock") {
			slog.Warn("Package lock detected. Waiting before retrying sensor installation", "Attempt", i+1, "RetryInterval", retryInterval)
			time.Sleep(retryInterval)
		} else {
			return stdout, stderr, err
		}
	}

	return nil, nil, fmt.Errorf("Error running %s: exceeded maximum retries: %d, stderr: %s", c, maxRetries, "Could not install the sensor")
}

// configureLinuxSensor configures the Falcon sensor on Linux using falconctl command.
func configureLinuxSensor(args []string) error {
	falconCtlCmd := fmt.Sprintf("%s%sfalconctl", falconLinuxInstallDir, string(os.PathSeparator))
	slog.Debug("Configuring Falcon sensor", "Command", falconCtlCmd, "Args", args)

	if _, err := exec.LookPath(falconCtlCmd); err != nil {
		return fmt.Errorf("Could not find falconctl: %s: %v", falconCtlCmd, err)
	}

	if _, stderr, err := utils.RunCmd(falconCtlCmd, args); err != nil {
		return fmt.Errorf("Error running falconctl: %v, stderr: %s", err, string(stderr))
	}

	return nil
}
