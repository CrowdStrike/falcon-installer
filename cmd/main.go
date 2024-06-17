package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/crowdstrike/falcon-installer/internal/version"
	"github.com/crowdstrike/falcon-installer/pkg/dpkg"
	"github.com/crowdstrike/falcon-installer/pkg/rpm"
	"github.com/crowdstrike/falcon-installer/pkg/systemd"
	"github.com/crowdstrike/falcon-installer/pkg/utils"
	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/sensor_download"
	"github.com/crowdstrike/gofalcon/falcon/client/sensor_update_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
)

var (
	logger *slog.Logger

	adminUser        = "root"
	targetOS         = "linux"
	arch             = "x86_64"
	enterpriseLinux  = []string{"rhel", "centos", "oracle", "almalinux", "rocky"}
	falconInstallDir = "/opt/CrowdStrike"
	defaultTmpDir    = fmt.Sprintf("%s%s%s", os.TempDir(), string(os.PathSeparator), "falcon")
	logFile          = fmt.Sprintf("%s%s%s", defaultTmpDir, string(os.PathSeparator), "falcon-installer.log")
	tmpDir           *string
	logToFile        *bool
	falconArgs       = []string{}
)

type Writer struct {
	stdout *os.File
	file   *os.File
}

const gpgPublicKey = `-----BEGIN PGP PUBLIC KEY BLOCK-----

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
=du8f
-----END PGP PUBLIC KEY BLOCK-----
`

func init() {
	switch targetOS = runtime.GOOS; targetOS {
	case "linux":
		targetOS = "linux"
		falconArgs = []string{"-sf"}
	case "windows":
		targetOS = "windows"
		falconArgs = []string{"/install", "/quiet"}
	default:
		if targetOS == "darwin" {
			targetOS = "macos"
		}
		log.Fatalf("Unsupported OS: %s\n", targetOS)
	}

	switch arch = runtime.GOARCH; arch {
	case "amd64":
		arch = "x86_64"
	case "arm64":
		arch = "arm64"
	case "s390x":
		arch = "s390x"
	case "386":
		arch = "x86"
	default:
		log.Fatalf("Unsupported OS architecture: %s\n", arch)
	}
}

func main() {
	osName := ""
	osVersion := ""
	cid := ""
	var gpgkey *string

	logLevel := slog.LevelInfo
	falconInstalled := false
	install := false
	writer := &Writer{stdout: os.Stdout}

	var err error

	clientId := flag.String("client-id", os.Getenv("FALCON_CLIENT_ID"), "Client ID for accessing CrowdStrike Falcon Platform (default taken from FALCON_CLIENT_ID env)")
	clientSecret := flag.String("client-secret", os.Getenv("FALCON_CLIENT_SECRET"), "Client Secret for accessing CrowdStrike Falcon Platform (default taken from FALCON_CLIENT_SECRET)")
	memberCID := flag.String("member-cid", os.Getenv("FALCON_MEMBER_CID"), "Member CID for MSSP (for cases when OAuth2 authenticates multiple CIDs)")
	clientCloud := flag.String("cloud", os.Getenv("FALCON_CLOUD"), "Falcon cloud abbreviation (us-1, us-2, eu-1, us-gov-1)")
	tmpDir = flag.String("tmpdir", defaultTmpDir, "Temporary directory for downloading files")
	falconCID := flag.String("cid", os.Getenv("FALCON_CID"), "Falcon Customer ID")
	falconToken := flag.String("provisioning-token", os.Getenv("FALCON_PROVISIONING_TOKEN"), "The provisioning token to use for installing the sensor")
	falconTags := flag.String("tags", os.Getenv("FALCON_TAGS"), "A comma seperated list of tags for sensor grouping.")
	falconAPD := flag.String("apd", os.Getenv("FALCON_APD"), "Configures if the proxy should be enabled or disabled, By default, the proxy is enabled.")
	falconAPH := flag.String("aph", os.Getenv("FALCON_APH"), "The proxy host for the sensor to use when communicating with CrowdStrike")
	falconAPP := flag.String("app", os.Getenv("FALCON_APP"), "The proxy port for the sensor to use when communicating with CrowdStrike")
	updatePolicyName := flag.String("sensor-update-policy", os.Getenv("FALCON_APP"), "The sensor update policy to use for sensor installation")
	debugLevel := flag.Bool("verbose", false, "Enable verbose output")
	logToFile = flag.Bool("enable-file-logging", false, fmt.Sprintf("Log output to file %s", logFile))

	if targetOS == "linux" && rpm.IsRpmInstalled() {
		gpgkey = flag.String("gpg-key", os.Getenv("FALCON_GPG_KEY"), "Falcon GPG key to import")
	}

	versionFlag := flag.Bool("version", false, "Print version information and exit")
	flag.Parse()

	if *versionFlag {
		fmt.Printf("falcon-installer %s\n", version.Version)
		os.Exit(0)
	}

	//create tmp directory if it does not exist
	if _, err := os.Stat(*tmpDir); os.IsNotExist(err) {
		if err := os.MkdirAll(*tmpDir, 0700); err != nil {
			log.Fatalf("Error creating temporary directory: %v", err)
		}
	}

	if *updatePolicyName == "" {
		*updatePolicyName = "platform_default"
	}

	if *debugLevel {
		logLevel = slog.LevelDebug
	}
	handlerOpts := &slog.HandlerOptions{
		Level: logLevel,
	}

	if *logToFile {
		logFile := fmt.Sprintf("%s%s%s", *tmpDir, string(os.PathSeparator), "falcon-installer.log")
		file, _ := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		writer = &Writer{file: file}
	}
	logger = slog.New(slog.NewTextHandler(writer, handlerOpts))

	if targetOS == "windows" && !utils.IsWindowsAdmin() {
		log.Fatal("You must run this program as an Administrator")
	}

	user := os.Getuid()
	if targetOS == "linux" && user != 0 {
		log.Fatal("You must run this program as root")
	}

	osName, osVersion, err = readOSRelease()
	if err != nil {
		log.Fatalf("%v", err)
	}

	logger.Debug("Identified operating system", "OS", osName, "Version", osVersion)
	osVersion = strings.Split(osVersion, ".")[0]

	if *clientId == "" {
		log.Fatalf("FALCON_CLIENT_ID is not set. Please provide your OAuth2 API Client ID for authentication with the CrowdStrike Falcon platform. See https://falcon.crowdstrike.com/api-clients-and-keys/clients to create or update OAuth2 credentials.")
	}
	if *clientSecret == "" {
		log.Fatalf("FALCON_CLIENT_SECRET is not set. Please provide your OAuth2 API Client Secret for authentication with the CrowdStrike Falcon platform. See https://falcon.crowdstrike.com/api-clients-and-keys/clients to create or update OAuth2 credentials.")
	}

	if *falconCID != "" {
		falconArgs = append(falconArgs, osArgHandler("cid", *falconCID))
	}
	if *falconToken != "" {
		falconArgs = append(falconArgs, osArgHandler("provisioning-token", *falconToken))
	}
	if *falconTags != "" {
		falconArgs = append(falconArgs, osArgHandler("tags", *falconTags))
	}
	if *falconAPD != "" {
		falconArgs = append(falconArgs, osArgHandler("apd", *falconAPD))
	}
	if *falconAPH != "" {
		falconArgs = append(falconArgs, osArgHandler("aph", *falconAPH))
	}
	if *falconAPP != "" {
		falconArgs = append(falconArgs, osArgHandler("app", *falconAPP))
	}

	client, err := falcon.NewClient(&falcon.ApiConfig{
		ClientId:          *clientId,
		ClientSecret:      *clientSecret,
		MemberCID:         *memberCID,
		Cloud:             falcon.Cloud(*clientCloud),
		Context:           context.Background(),
		UserAgentOverride: fmt.Sprintf("falcon-installer/%s", version.Version),
	})
	if err != nil {
		log.Fatalf("Error creating Falcon client: %v", err)
	}

	if targetOS == "linux" {
		falconInstalled, err = packageQuery("falcon-sensor")
		if err != nil {
			log.Fatalf("Error querying package manager: %v", err)
		}
	}

	if targetOS == "windows" {
		falconInstalled, err = scQuery("csagent")
		if err != nil {
			log.Fatalf("Error querying service manager: %v", err)
		}
	}

	if !falconInstalled {
		install = true

		if rpm.IsRpmInstalled() {
			logger.Info("Installing CrowdStrike Falcon GPG key")
			if *gpgkey != "" {
				logger.Debug("Using provided GPG key", "GPG Key", *gpgkey)
				rpm.GpgKeyImport(*gpgkey)
			} else {
				gpgKeyFile := fmt.Sprintf("%s%s%s", *tmpDir, string(os.PathSeparator), "falcon-gpg-key")
				err = os.WriteFile(gpgKeyFile, []byte(gpgPublicKey), 0600)
				if err != nil {
					log.Fatalf("Error writing GPG key to file: %v", err)
				}
				logger.Debug("Using embedded GPG key", "GPG Key", gpgKeyFile, "Key", gpgPublicKey)
				rpm.GpgKeyImport(gpgKeyFile)
			}

		}

		if !slices.Contains(falconArgs, "cid") {
			cid, err = getCID(context.Background(), client)
			if err != nil {
				log.Fatalf("Error getting Falcon CID: %v", err)
			}
			logger.Debug("Found suitable Falcon Customer ID (CID)", "CID", cid)
			falconArgs = append(falconArgs, osArgHandler("cid", cid))
		}

		sensor := querySuitableSensor(client, osName, osVersion, "latest", *updatePolicyName)
		if sensor == nil {
			log.Fatalf("Could not find Falcon sensor for '%s' '%s'", osName, osVersion)
		}

		path := download(client, sensor, *tmpDir, *sensor.Name)
		installSensor(path, falconArgs)
	} else {
		logger.Info("Sensor is already installed. Skipping download and installation")
	}

	if targetOS == "linux" {
		if len(falconArgs) > 1 {
			configureLinuxSensor(falconArgs)
		} else {
			logger.Info("Skipping Falcon sensor configuration. No additional configuration required")
		}

		if install {
			systemd.RestartService("falcon-sensor")
		}
	}

	logger.Info("Falcon sensor installation complete")
}

func (w *Writer) Write(p []byte) (n int, err error) {
	if w.stdout != nil {
		n, err = w.stdout.Write(p)
		if err != nil {
			return
		}
	}

	if w.file != nil {
		n, err = w.file.Write(p)
		if err != nil {
			return 0, err
		}
	}

	return n, nil
}

func osArgHandler(arg, val string) string {
	windowsFalconMap := map[string]string{
		"cid":                "CID",
		"provisioning-token": "ProvToken",
		"tags":               "GROUPING_TAGS",
		"apd":                "PROXYDISABLE",
		"aph":                "APP_PROXYNAME",
		"app":                "APP_PROXYPORT",
	}

	switch targetOS {
	case "windows":
		return fmt.Sprintf("%s=%s", windowsFalconMap[arg], val)
	default:
		return fmt.Sprintf("--%s=%s", arg, val)
	}
}

func readOSRelease() (osName, osVersion string, err error) {
	switch targetOS {
	case "linux":
		linuxOsRelease := "/etc/os-release"
		data, err := os.ReadFile(linuxOsRelease)
		if err != nil {
			return "", "", fmt.Errorf("Error reading %s: %w", linuxOsRelease, err)
		}

		logger.Debug(fmt.Sprintf("Reading %s", linuxOsRelease), "output", string(data))
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "ID=") {
				osName = strings.Trim(strings.TrimPrefix(line, "ID="), "\"")
			} else if strings.HasPrefix(line, "VERSION_ID=") {
				osVersion = strings.Trim(strings.TrimPrefix(line, "VERSION_ID="), "\"")
			}
		}
		return osName, osVersion, nil
	case "windows":
		return "windows", "", nil
	default:
		return "", "", fmt.Errorf("Unsupported OS: %s", targetOS)
	}
}

func getSensorUpdatePolicies(client *client.CrowdStrikeAPISpecification, policyName string, arch string) string {
	var filter *string
	csPlatformName := ""

	switch targetOS {
	case "windows":
		csPlatformName = "windows"
	default:
		csPlatformName = "Linux"
	}

	f := fmt.Sprintf("platform_name:~\"%s\"+name.raw:\"%s\"", csPlatformName, policyName)
	logger.Debug("Sensor Update Policy Query", slog.String("Filter", f))
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
			switch targetOS {
			case "linux":
				switch arch {
				case "arm64":
					for _, variant := range policy.Settings.Variants {
						if strings.Contains(strings.ToLower(*variant.Platform), "arm64") {
							senserVersion = *variant.SensorVersion
							logger.Debug("arm64 sensor update policy versions", "Version", senserVersion)
						}
					}
				case "s390x":
					for _, variant := range policy.Settings.Variants {
						if strings.Contains(strings.ToLower(*variant.Platform), "zlinux") {
							senserVersion = *variant.SensorVersion
							logger.Debug("zLinux sensor update policy version", "Version", senserVersion)
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

	logger.Debug("Found suitable Falcon sensor version from sensor update policies", "Version", senserVersion)
	return senserVersion
}

func getSensors(client *client.CrowdStrikeAPISpecification, osName string, osVersion string, arch string, updatePolicyName string) []*models.DomainSensorInstallerV2 {
	var filter *string

	sensorVersion := getSensorUpdatePolicies(client, updatePolicyName, arch)
	if osName != "" {
		if slices.Contains(enterpriseLinux, strings.ToLower(osName)) {
			logger.Debug("Adding wildcard for Enterprise Linux", "Distros", enterpriseLinux, "OS", osName, "Version", osVersion)
			osName = "*RHEL*"
		}

		f := fmt.Sprintf("os:~\"%s\"+os_version:\"*%s*\"+architectures:\"%s\"", osName, osVersion, arch)
		if sensorVersion != "" {
			f = fmt.Sprintf("%s+version:\"%s\"", f, sensorVersion)
		}
		logger.Debug("Sensor Installer Query", slog.String("Filter", f))
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
		logger.Debug(*sensor.Description)
		if strings.Contains(*sensor.Description, "Falcon SIEM Connector") {
			continue
		}
		payload.Resources[k] = sensor
		k++
	}

	return payload.Resources[:k]
}

func querySuitableSensor(client *client.CrowdStrikeAPISpecification, osName, osVersion, sensorVersion, updatePolicyName string) *models.DomainSensorInstallerV2 {
	for _, sensor := range getSensors(client, osName, osVersion, arch, updatePolicyName) {
		if strings.Contains(*sensor.OsVersion, osVersion) {
			if *sensor.Version == sensorVersion || sensorVersion == "latest" {
				logger.Debug("Found suitable Falcon sensor", "Version", *sensor.Version)
				return sensor
			}
		}
	}
	return nil
}

func getCID(ctx context.Context, client *client.CrowdStrikeAPISpecification) (string, error) {
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

func openFileForWriting(dir, filename string) (*os.File, error) {
	if strings.Contains(filename, "/") {
		return nil, fmt.Errorf("Refusing to download: '%s' includes '/' character", filename)
	}
	path := filepath.Join(dir, filename)
	safeLocation := filepath.Clean(path)
	if strings.Contains(safeLocation, "..") {
		return nil, fmt.Errorf("Refusing to download: Path '%s' looks suspicious", safeLocation)
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	return os.OpenFile(safeLocation, os.O_CREATE|os.O_WRONLY, 0600)
}

func download(client *client.CrowdStrikeAPISpecification, sensor *models.DomainSensorInstallerV2, dir, filename string) string {
	file, err := openFileForWriting(dir, filename)
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
	logger.Debug(fmt.Sprintf("Downloaded %s to %s", *sensor.Description, fullPath))
	return fullPath
}

func installSensor(path string, args []string) {
	env := ""
	switch targetOS {
	case "linux":
		if cmd, err := exec.LookPath("/usr/bin/dnf"); err == nil {
			args := []string{"install", "-q", "-y", path}
			runCmd(cmd, env, args)
		} else if cmd, err := exec.LookPath("/usr/bin/yum"); err == nil {
			args := []string{"install", "-q", "-y", path}
			runCmd(cmd, env, args)
		} else if cmd, err := exec.LookPath("/usr/bin/zypper"); err == nil {
			args := []string{"install", "--quiet", "-y", path}
			runCmd(cmd, env, args)
		} else if cmd, err := exec.LookPath("/usr/bin/apt-get"); err == nil {
			args := []string{"install", "-y", path}
			env = "DEBIAN_FRONTEND=noninteractive"
			runCmd(cmd, env, args)
		} else if cmd, err := exec.LookPath("/usr/bin/dpkg"); err == nil {
			args := []string{"install", "--qq", "-y", path}
			env = "DEBIAN_FRONTEND=noninteractive"
			runCmd(cmd, env, args)
		} else {
			log.Fatalf("Unsupported package manager: %v", err)
		}
	case "windows":
		runCmd(path, env, args)
	}

}

func configureLinuxSensor(args []string) {
	falconCtlCmd := fmt.Sprintf("%s%sfalconctl", falconInstallDir, string(os.PathSeparator))
	if _, err := exec.LookPath(falconCtlCmd); err == nil {
		utils.RunCmd(exec.Command(falconCtlCmd, args...))
	} else {
		log.Fatalf("Could not find falconctl: %s", falconCtlCmd)
	}
}

func runCmd(cmnd string, env string, args []string) {
	var stdout, stderr bytes.Buffer

	cmd := exec.Command(cmnd, args...)
	if env != "" {
		cmd.Env = os.Environ()
		cmd.Env = append(cmd.Env, env)
	}

	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if *logToFile {
		logfile, err := os.OpenFile("/tmp/falcon/falcon-installer.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			log.Fatalf("Error opening log file: %v", err)
		}
		defer logfile.Close()

		cmd.Stdout = logfile
		cmd.Stderr = logfile
	}

	logger.Debug(fmt.Sprintf("Command: %s %s", cmnd, strings.Join(args, " ")))
	if err := cmd.Run(); err != nil {
		log.Fatalf("Error running cli tool: %v", err)
	}
}

func packageQuery(name string) (bool, error) {
	if rpm.IsRpmInstalled() {
		pkg, err := rpm.Query(name)
		if err != nil {
			return false, err
		}
		return pkg, nil
	} else if dpkg.IsDpkgInstalled() {
		pkg, err := dpkg.Query(name)
		if err != nil {
			return false, err
		}
		return pkg, nil
	}

	return false, fmt.Errorf("Unsupported package manager for package query")
}

func scQuery(name string) (bool, error) {
	var err error
	if cmd, err := exec.LookPath("sc.exe"); err != nil {
		args := []string{"query", name}

		if _, stderr, err := utils.RunCmd(exec.Command(cmd, args...)); err != nil {
			if strings.Contains(string(stderr), "does not exist") {
				return false, nil
			}
			return false, fmt.Errorf("Error running sc query: %v", err)
		}

		return true, nil
	}

	return false, err
}

type void struct{}
