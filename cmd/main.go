package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"os"
	"runtime"
	"strings"

	"github.com/crowdstrike/falcon-installer/internal/version"
	"github.com/crowdstrike/falcon-installer/pkg/installer"
	"github.com/crowdstrike/falcon-installer/pkg/rpm"
	"github.com/crowdstrike/falcon-installer/pkg/utils/osutils"
)

var (
	targetOS = "linux"
	arch     = "x86_64"

	defaultTmpDir = fmt.Sprintf("%s%s%s", os.TempDir(), string(os.PathSeparator), "falcon")
	logFile       = fmt.Sprintf("%s%s%s", defaultTmpDir, string(os.PathSeparator), "falcon-installer.log")
)

func init() {
	switch targetOS = runtime.GOOS; targetOS {
	case "linux":
		targetOS = "linux"
	case "windows":
		targetOS = "windows"
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
	default:
		log.Fatalf("Unsupported OS architecture: %s\n", arch)
	}

	// Check if running with privileges to install Falcon sensor
	privs, err := osutils.RunningWithPrivileges(targetOS)
	if !privs || err != nil {
		log.Fatalf("%v", err)
	}
}

func main() {
	var gpgKeyFile *string

	// API CLI flags
	clientId := flag.String("client-id", os.Getenv("FALCON_CLIENT_ID"), "Client ID for accessing CrowdStrike Falcon Platform (default taken from FALCON_CLIENT_ID env)")
	clientSecret := flag.String("client-secret", os.Getenv("FALCON_CLIENT_SECRET"), "Client Secret for accessing CrowdStrike Falcon Platform (default taken from FALCON_CLIENT_SECRET)")
	memberCID := flag.String("member-cid", os.Getenv("FALCON_MEMBER_CID"), "Member CID for MSSP (for cases when OAuth2 authenticates multiple CIDs)")
	cloud := flag.String("cloud", os.Getenv("FALCON_CLOUD"), "Falcon cloud abbreviation (us-1, us-2, eu-1, us-gov-1)")

	// Falcon sensor flags
	falconCID := flag.String("cid", os.Getenv("FALCON_CID"), "Falcon Customer ID")
	falconToken := flag.String("provisioning-token", os.Getenv("FALCON_PROVISIONING_TOKEN"), "The provisioning token to use for installing the sensor")
	falconTags := flag.String("tags", os.Getenv("FALCON_TAGS"), "A comma seperated list of tags for sensor grouping.")
	falconAPD := flag.String("apd", os.Getenv("FALCON_APD"), "Configures if the proxy should be enabled or disabled, By default, the proxy is enabled.")
	falconAPH := flag.String("aph", os.Getenv("FALCON_APH"), "The proxy host for the sensor to use when communicating with CrowdStrike")
	falconAPP := flag.String("app", os.Getenv("FALCON_APP"), "The proxy port for the sensor to use when communicating with CrowdStrike")
	updatePolicyName := flag.String("sensor-update-policy", os.Getenv("FALCON_SENSOR_UPDATE_POLICY_NAME"), "The sensor update policy name to use for sensor installation")

	// General flags
	userAgentAdd := flag.String("user-agent", "", "User agent string to add to use for API requests in addition to the default")
	tmpDir := flag.String("tmpdir", defaultTmpDir, "Temporary directory for downloading files")
	verbose := flag.Bool("verbose", false, "Enable verbose output")
	quiet := flag.Bool("quiet", false, "Supress all log output")
	enableLogging := flag.Bool("enable-logging", false, fmt.Sprintf("Output logs to file %s", logFile))
	versionFlag := flag.Bool("version", false, "Print version information and exit")

	// Linux specific flags
	if targetOS == "linux" && rpm.IsRpmInstalled() {
		gpgKeyFile = flag.String("gpg-key", os.Getenv("FALCON_GPG_KEY"), "Falcon GPG key to import")
	}

	flag.Parse()

	if *versionFlag {
		fmt.Printf("falcon-installer %s <commit: %s>\n", version.Version, version.Commit)
		os.Exit(0)
	}

	if *clientId == "" {
		log.Fatalf("--client-id or FALCON_CLIENT_ID is not set. Please provide your OAuth2 API Client ID for authentication with the CrowdStrike Falcon platform. See https://falcon.crowdstrike.com/api-clients-and-keys/clients to create or update OAuth2 credentials.")
	}
	if *clientSecret == "" {
		log.Fatalf("--client-secret or FALCON_CLIENT_SECRET is not set. Please provide your OAuth2 API Client Secret for authentication with the CrowdStrike Falcon platform. See https://falcon.crowdstrike.com/api-clients-and-keys/clients to create or update OAuth2 credentials.")
	}

	if *enableLogging && !*quiet {
		logFile := fmt.Sprintf("%s%s%s", *tmpDir, string(os.PathSeparator), "falcon-installer.log")
		file, _ := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		log.SetOutput(file)
	}

	if *verbose {
		slog.SetLogLoggerLevel(slog.LevelDebug)
		slog.Debug("Starting falcon-installer", "Version", version.Version)
		slog.Debug("Verbose output enabled")
	}

	if *quiet {
		log.SetOutput(io.Discard)
	}

	//create tmp directory if it does not exist
	if _, err := os.Stat(*tmpDir); os.IsNotExist(err) {
		if err := os.MkdirAll(*tmpDir, 0700); err != nil {
			log.Fatalf("Error creating temporary directory: %v", err)
		}
	}

	// Set default sensor update policy name
	if *updatePolicyName == "" {
		*updatePolicyName = "platform_default"
	}

	osName, osVersion, err := osutils.ReadEtcRelease(targetOS)
	if err != nil {
		log.Fatalf("%v", err)
	}

	slog.Debug("Identified operating system", "OS", osName, "Version", osVersion)
	osVersion = strings.Split(osVersion, ".")[0]

	userAgent := fmt.Sprintf("falcon-installer/%s", version.Version)

	if *userAgentAdd != "" {
		userAgent = fmt.Sprintf("%s %s", userAgent, *userAgentAdd)
	}
	slog.Debug("User agent string", "UserAgent", userAgent)

	fc := installer.FalconSensorCLI{
		CID:               *falconCID,
		ProvisioningToken: *falconToken,
		Tags:              *falconTags,
		APD:               *falconAPD,
		APH:               *falconAPH,
		APP:               *falconAPP,
	}
	slog.Debug("Falcon sensor CLI options", "CID", fc.CID, "ProvisioningToken", fc.ProvisioningToken, "Tags", fc.Tags, "APD", fc.APD, "APH", fc.APH, "APP", fc.APP)

	fi := installer.FalconInstaller{
		ClientId:     *clientId,
		ClientSecret: *clientSecret,
		Cloud:        *cloud,
		MemberCID:    *memberCID,

		SensorUpdatePolicyName: *updatePolicyName,
		OsName:                 osName,
		OsVersion:              osVersion,
		OS:                     targetOS,
		Arch:                   arch,
		TmpDir:                 *tmpDir,
		UserAgent:              userAgent,

		SensorConfig: fc,
	}

	if isFlag("gpg-key") {
		fi.GpgKeyFile = *gpgKeyFile
	}

	slog.Debug("Falcon installer options", "Cloud", fi.Cloud, "MemberCID", fi.MemberCID, "SensorUpdatePolicyName", fi.SensorUpdatePolicyName, "GpgKeyFile", fi.GpgKeyFile, "TmpDir", fi.TmpDir, "OsName", fi.OsName, "OsVersion", fi.OsVersion, "OS", fi.OS, "Arch", fi.Arch, "UserAgent", fi.UserAgent)

	installer.Run(fi)
}

func isFlag(name string) bool {
	exists := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			exists = true
		}
	})
	return exists
}
