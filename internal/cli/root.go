// MIT License// MIT License
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

package cli

import (
	"fmt"
	"io"
	"log"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"

	"github.com/crowdstrike/falcon-installer/internal/config"
	"github.com/crowdstrike/falcon-installer/internal/version"
	"github.com/crowdstrike/falcon-installer/pkg/installer"
	"github.com/crowdstrike/falcon-installer/pkg/utils/osutils"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

var (
	progName   = "falcon-installer"
	cliVersion = fmt.Sprintf("%s %s <commit: %s>", progName, version.Version, version.Commit)
	targetOS   = "linux"
	arch       = "x86_64"

	defaultTmpDir                      = fmt.Sprint(os.TempDir(), string(os.PathSeparator), "falcon")
	defaultProvisioningWaitTime uint64 = 1200000
	defaultSensorUpdatePolicy          = "platform_default"
	defaultCloudRegion                 = "autodiscover"
	logFile                            = fmt.Sprint(defaultTmpDir, string(os.PathSeparator), "falcon-installer.log")
	cfg                         *config.Config
)

func init() {
	switch targetOS = runtime.GOOS; targetOS {
	case "linux":
		targetOS = "linux"
	case "windows":
		targetOS = "windows"
		defaultTmpDir = fmt.Sprint("C:\\Windows\\Temp", string(os.PathSeparator), "falcon")
		logFile = fmt.Sprint(defaultTmpDir, string(os.PathSeparator), "falcon-installer.log")
	case "darwin":
		targetOS = "macos"
	default:
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
}

// rootCmd returns the root command for the CLI.
func rootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:              progName,
		Short:            "A lightweight CrowdStrike Falcon sensor installer",
		Long:             "A lightweight, multi-platform CrowdStrike Falcon sensor installer written in Golang with consistent configuration flags across multiple operating systems.",
		Version:          cliVersion,
		PersistentPreRun: preRunConfig,
		PreRun: func(cmd *cobra.Command, _ []string) {
			if err := preRunValidation(cmd); err != nil {
				log.Fatalf("%v", err)
			}
		},
		Run: Run,
	}

	rootCmd.PersistentFlags().String("config", "", "A falcon-installer configuration file")
	rootCmd.PersistentFlags().String("tmpdir", defaultTmpDir, "Temporary directory for downloading files")
	rootCmd.PersistentFlags().Bool("quiet", false, "Suppress all log output")
	rootCmd.PersistentFlags().Bool("enable-file-logging", false, "Output logs to file")
	rootCmd.PersistentFlags().BoolP("help", "h", false, "Print usage information")
	rootCmd.PersistentFlags().BoolP("version", "v", false, "Print version information")
	rootCmd.PersistentFlags().Bool("verbose", false, "Enable verbose output")

	groups := map[string]*pflag.FlagSet{}

	// Falcon API flags
	apiFlag := pflag.NewFlagSet("FalconAPI", pflag.ExitOnError)
	apiFlag.String("client-id", "", "Client ID for accessing CrowdStrike Falcon Platform")
	apiFlag.String("client-secret", "", "Client Secret for accessing CrowdStrike Falcon Platform")
	apiFlag.String("access-token", "", "Access token for accessing CrowdStrike Falcon Platform")
	apiFlag.String("member-cid", "", "Member CID for MSSP (for cases when OAuth2 authenticates multiple CIDs)")
	apiFlag.String("cloud", defaultCloudRegion, "Falcon cloud abbreviation (e.g. us-1, us-2, eu-1, us-gov-1)")
	apiFlag.String("sensor-update-policy", defaultSensorUpdatePolicy, "The sensor update policy name to use for sensor installation")
	apiFlag.String("sensor-version", "", "The sensor version to update or install (overrides sensor-update-policy)")
	apiFlag.String("user-agent", "", "User agent string to append to use for API requests")
	rootCmd.Flags().AddFlagSet(apiFlag)
	err := viper.BindPFlags(apiFlag)
	if err != nil {
		log.Fatalf("Error binding falcon api flags: %v", err)
	}
	groups["Falcon API Flags"] = apiFlag

	// Cloud Provider flags
	cspFlag := pflag.NewFlagSet("Vault", pflag.ExitOnError)
	cspFlag.String("oci-compartment-id", "", "OCI Compartment ID")
	cspFlag.String("oci-vault-name", "", "OCI Vault Name")
	rootCmd.Flags().AddFlagSet(cspFlag)
	err = viper.BindPFlags(cspFlag)
	if err != nil {
		log.Fatalf("Error binding vault flags: %v", err)
	}
	groups["Vault Flags"] = cspFlag

	// Falcon update flags
	updateFlag := pflag.NewFlagSet("Update", pflag.ExitOnError)
	updateFlag.Bool("update", false, "Update the Falcon sensor for when sensor update policies are not in use")
	updateFlag.Bool("upgrade", false, "Upgrade the Falcon sensor for when sensor update policies are not in use")
	err = updateFlag.MarkHidden("upgrade")
	if err != nil {
		log.Fatalf("Error marking upgrade flag as hidden: %v", err)
	}
	rootCmd.Flags().AddFlagSet(updateFlag)
	err = viper.BindPFlags(updateFlag)
	if err != nil {
		log.Fatalf("Error binding falcon uninstall flags: %v", err)
	}
	groups["Falcon Update Flags"] = updateFlag

	// Falcon uninstall flags
	uninstallFlag := pflag.NewFlagSet("Uninstall", pflag.ExitOnError)
	uninstallFlag.Bool("uninstall", false, "Uninstall the Falcon sensor")
	rootCmd.Flags().AddFlagSet(uninstallFlag)
	err = viper.BindPFlags(uninstallFlag)
	if err != nil {
		log.Fatalf("Error binding falcon uninstall flags: %v", err)
	}
	groups["Falcon Uninstall Flags"] = uninstallFlag

	// Falcon sensor flags
	falconFlag := pflag.NewFlagSet("Falcon", pflag.ExitOnError)
	falconFlag.String("cid", "", "Falcon Customer ID. Optional when OAuth2 credentials are provided")
	falconFlag.String("provisioning-token", "",
		"The provisioning token to use for installing the sensor. If not provided, the API will attempt to retrieve a token")
	falconFlag.String("tags", "", "A comma separated list of tags for sensor grouping")
	falconFlag.String("maintenance-token", "", "Maintenance token for uninstalling the sensor or configuring sensor settings")

	if targetOS != "macos" {
		falconFlag.Bool("disable-proxy", false, "Disable the sensor proxy settings")
		falconFlag.String("proxy-host", "", "The proxy host for the sensor to use when communicating with CrowdStrike")
		falconFlag.String("proxy-port", "", "The proxy port for the sensor to use when communicating with CrowdStrike")
	}

	rootCmd.Flags().AddFlagSet(falconFlag)
	err = viper.BindPFlags(falconFlag)
	if err != nil {
		log.Fatalf("Error binding falcon sensor flags: %v", err)
	}
	groups["Falcon Sensor Flags"] = falconFlag

	switch targetOS {
	case "linux":
		// Linux sensor flags
		linuxFlag := pflag.NewFlagSet("Linux", pflag.ExitOnError)
		linuxFlag.String("gpg-key", "", "Falcon GPG key to import")
		linuxFlag.Bool("configure-image", false, "Use when installing the sensor in an image")
		rootCmd.Flags().AddFlagSet(linuxFlag)
		err = viper.BindPFlags(linuxFlag)
		if err != nil {
			log.Fatalf("Error binding linux flags: %v", err)
		}
		groups["Linux Installation Flags"] = linuxFlag

	case "macos":
		// MacOS sensor flags
		macosFlag := pflag.NewFlagSet("MacOS", pflag.ExitOnError)
		macosFlag.Bool("configure-image", false, "Use when installing the sensor in an image")
		rootCmd.Flags().AddFlagSet(macosFlag)
		err = viper.BindPFlags(macosFlag)
		if err != nil {
			log.Fatalf("Error binding macos flags: %v", err)
		}
		groups["MacOS Installation Flags"] = macosFlag

	case "windows":
		// Windows sensor flags
		winFlag := pflag.NewFlagSet("Windows", pflag.ExitOnError)
		winFlag.Bool("restart", false, "Allow the system to restart after sensor installation if necessary")
		winFlag.String("pac-url", "", "Configure a proxy connection using the URL of a PAC file when communicating with CrowdStrike")
		winFlag.Bool("disable-provisioning-wait", false, "Disabling allows the Windows installer more provisioning time")
		winFlag.Uint64("provisioning-wait-time", defaultProvisioningWaitTime, "The number of milliseconds to wait for the sensor to provision")
		winFlag.Bool("disable-start", false, "Prevent the sensor from starting after installation until a reboot occurs")
		winFlag.Bool("vdi", false, "Enable virtual desktop infrastructure mode")
		winFlag.Bool("configure-image", false, "Use when installing the sensor in an image")
		rootCmd.Flags().AddFlagSet(winFlag)
		err = viper.BindPFlags(winFlag)
		if err != nil {
			log.Fatalf("Error binding windows flags: %v", err)
		}
		groups["Windows Installation Flags"] = winFlag
	}

	rootCmd.SetUsageTemplate(fmt.Sprintf(usageTemplate, groupUsageFunc(rootCmd, groups)))

	return rootCmd
}

// preRunConfig sets up the environment before running the command.
func preRunConfig(cmd *cobra.Command, _ []string) {
	// Check if running with privileges to install Falcon sensor
	privs, err := osutils.RunningWithPrivileges(targetOS)
	if !privs || err != nil {
		log.Fatalf("%v", err)
	}

	viper.SetEnvPrefix("FALCON")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	viper.AutomaticEnv()
	bindCobraFlags(cmd)

	cfgFile := viper.GetString("config")
	if cfgFile != "" {
		viper.AddConfigPath(".")
		viper.SetConfigFile(cfgFile)

		cFileType := filepath.Ext(cfgFile)
		if cFileType == ".settings" {
			viper.SetConfigType("json")
		}

		if err := viper.ReadInConfig(); err != nil {
			if err, ok := err.(viper.ConfigFileNotFoundError); ok {
				log.Fatal(err)
			}
		}

		// Check if the config file is an INI file and handle default section
		if cFileType == ".ini" {
			defaultSection := viper.Sub("falcon")
			if defaultSection != nil {
				for k, v := range defaultSection.AllSettings() {
					viper.Set(k, v)
				}
			}
		}

		// Check if the config file is a JSON file for Azure VM Extension
		if cFileType == ".settings" && viper.IsSet("runtimeSettings") {
			handler := viper.Sub("runtimeSettings.0.handlerSettings")
			publicSettings := handler.Sub("publicSettings")
			if publicSettings != nil {
				for k, v := range publicSettings.AllSettings() {
					viper.Set(k, v)
				}
			}

			protectedSettings := handler.Get("protectedSettings")
			if protectedSettings != nil {
				thumbprint := handler.GetString("protectedSettingsCertThumbprint")

				executablePath, err := os.Executable()
				if err != nil {
					fmt.Println("Error:", err)
					return
				}

				// Get the directory of the executable.
				executableDir := filepath.Dir(executablePath)
				parentDir := filepath.Dir(executableDir)
				pSettings, err := osutils.DecryptProtectedSettings(viper.GetString("runtimeSettings.0.handlerSettings.protectedSettings"), thumbprint, parentDir)
				if err != nil {
					log.Fatalf("failed to decrypt Azure protected settings: %v", err)
				} else {
					for k, v := range pSettings {
						viper.Set(k, v)
					}
				}
			}
		}
	}

	// Process falcon_ prefixed configuration keys
	processFalconPrefixedConfigKeys()

	verbose := viper.GetBool("verbose")
	quiet := viper.GetBool("quiet")
	enableFileLogging := viper.GetBool("enable_file_logging")
	tmpdir := viper.GetString("tmpdir")

	if _, err := os.Stat(tmpdir); os.IsNotExist(err) {
		if err := os.MkdirAll(tmpdir, 0700); err != nil {
			log.Fatalf("Error creating temporary directory: %v", err)
		}
	}

	if tmpdir != defaultTmpDir {
		logFile = fmt.Sprintf("%s%s%s", tmpdir, string(os.PathSeparator), "falcon-installer.log")
	}

	if quiet {
		log.SetOutput(io.Discard)
	}

	if !quiet && enableFileLogging {
		file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			log.Fatalf("Error opening log file: %v", err)
		}
		log.SetOutput(file)
	}

	if verbose {
		slog.SetLogLoggerLevel(slog.LevelDebug)
		slog.Debug("Starting falcon-installer", "Version", version.Version)
		slog.Debug("Verbose output enabled")
	}

	// Print config file after all the logging is configured
	slog.Debug("Using the following configuration file", "config", viper.ConfigFileUsed())

	cfg, err = config.Load()
	if err != nil {
		log.Fatalf("Error loading configuration: %v", err)
	}
}

// preRunValidation validates the input flags before running the command.
func preRunValidation(cmd *cobra.Command) error {
	viper := viper.GetViper()

	// Silence usage if an error occurs since the usage string does not provide additional information
	// on why the command failed.
	cmd.SilenceUsage = true

	// Skip the validation if uninstall flag is set
	if viper.GetBool("uninstall") || viper.GetBool("update") || viper.GetBool("upgrade") {
		return nil
	}

	// ClientID and ClientSecret cannot be set when Access Token is provided
	if viper.IsSet("access-token") && (viper.IsSet("client_id") || viper.IsSet("client_secret")) {
		return fmt.Errorf("cannot specify Client ID or Client Secret when Access Token is provided")
	}

	// Region must be specified when using Access Token
	if viper.IsSet("access_token") && !viper.IsSet("cloud") {
		return fmt.Errorf("the Cloud region must be specified when using Access Token")
	}

	if !viper.IsSet("access_token") && !viper.IsSet("client_id") {
		return fmt.Errorf("the Client ID must be specified. See https://falcon.crowdstrike.com/api-clients-and-keys/clients to create or update OAuth2 credentials")
	}

	if !viper.IsSet("access_token") && !viper.IsSet("client_secret") {
		return fmt.Errorf("the Client Secret must be specified. See https://falcon.crowdstrike.com/api-clients-and-keys/clients to create or update OAuth2 credentials")
	}

	if viper.GetString("client_id") == "" {
		return fmt.Errorf("the Client ID cannot be empty")
	}

	if viper.GetString("client_secret") == "" {
		return fmt.Errorf("the Client Secret cannot be empty")
	}

	if err := inputValidation(viper.GetString("client_id"), "^[a-zA-Z0-9]{32}$"); err != nil {
		return fmt.Errorf("invalid OAuth Client ID format: %v", err)
	}

	if err := inputValidation(viper.GetString("client_secret"), "^[a-zA-Z0-9]{40}$"); err != nil {
		return fmt.Errorf("invalid OAuth Client Secret format: %v", err)
	}

	if err := inputValidation(viper.GetString("cid"), "^[0-9a-fA-F]{32}-[0-9a-fA-F]{2}$"); err != nil {
		return fmt.Errorf("invalid CID format: %v", err)
	}

	if err := inputValidation(viper.GetString("member_cid"), "^[0-9a-fA-F]{32}-[0-9a-fA-F]{2}$"); err != nil {
		return fmt.Errorf("invalid member CID format: %v", err)
	}

	if err := inputValidation(viper.GetString("cloud"), "^(autodiscover|us-1|us-2|eu-1|us-gov-1|gov1)$"); err != nil {
		return fmt.Errorf("invalid cloud region: %v", err)
	}

	if err := inputValidation(viper.GetString("tags"), "^[a-zA-Z0-9,_/-]+$"); err != nil {
		return fmt.Errorf("invalid Falcon Sensor tag format: %v", err)
	}

	sVer := viper.GetString("sensor_version")
	if sVer != "" {
		if err := inputValidation(sVer, "^[0-9]+.[0-9]+.[0-9]+$"); err != nil {
			return fmt.Errorf("invalid Falcon Sensor version format: %v", err)
		}
	}

	if viper.GetBool("proxy_disable") && (viper.GetString("proxy_host") != "" || viper.GetString("proxy_port") != "") {
		return fmt.Errorf("cannot specify proxy host or port when using --disable-proxy")
	}

	return nil
}

// Run is the main entry point for the root command.
func Run(_ *cobra.Command, _ []string) {
	if cfg.UserAgent != "" {
		cfg.UserAgent = fmt.Sprintf("falcon-installer/%s %s", version.Version, cfg.UserAgent)
	} else {
		cfg.UserAgent = fmt.Sprintf("falcon-installer/%s", version.Version)
	}
	slog.Debug("User agent string", "UserAgent", cfg.UserAgent)

	if targetOS == "windows" && cfg.ConfigureImage {
		cfg.SensorConfig.NoStart = true
	}

	osName, osVersion, err := osutils.ReadEtcRelease(targetOS)
	if err != nil {
		log.Fatalf("%v", err)
	}

	slog.Debug("Identified operating system", "OS", osName, "Version", osVersion)
	osVersion = strings.Split(osVersion, ".")[0]

	cfg.Arch = arch
	cfg.OSType = targetOS
	cfg.OsName = osName
	cfg.OsVersion = osVersion

	switch {
	case viper.GetBool("uninstall"):
		installer.Uninstall(cfg.FalconInstaller)
	case viper.GetBool("update"), viper.GetBool("upgrade"):
		installer.Update(cfg.FalconInstaller)
	default:
		slog.Debug("Falcon sensor CLI options", "CID", cfg.SensorConfig.CID, "ProvisioningToken", cfg.SensorConfig.ProvisioningToken,
			"Tags", cfg.SensorConfig.Tags, "DisableProxy", cfg.SensorConfig.ProxyDisable, "ProxyHost", cfg.SensorConfig.ProxyHost,
			"ProxyPort", cfg.SensorConfig.ProxyPort)
		slog.Debug("Falcon installer options", "Cloud", cfg.Cloud, "MemberCID", cfg.MemberCID, "SensorUpdatePolicyName", cfg.SensorUpdatePolicyName,
			"GpgKeyFile", cfg.GpgKeyFile, "TmpDir", cfg.TmpDir, "OsName", cfg.OsName, "OsVersion", cfg.OsVersion, "OS", cfg.OSType, "Arch", cfg.Arch)
		installer.Run(cfg.FalconInstaller)
	}
}

// inputValidation validates the input against the provided regex pattern.
func inputValidation(input, pattern string) error {
	if input == "" {
		return nil
	}

	if !regexp.MustCompile(pattern).MatchString(input) {
		return fmt.Errorf("pattern does not match: %s", pattern)
	}
	return nil
}

// usageTemplate is a modified version of the default usage template.
var usageTemplate = `Usage:{{if .Runnable}}
  {{.UseLine}}{{end}}{{if .HasAvailableSubCommands}}
  {{.CommandPath}} [command]{{end}}{{if gt (len .Aliases) 0}}

Aliases:
  {{.NameAndAliases}}{{end}}{{if .HasExample}}

Examples:
{{.Example}}{{end}}{{if .HasAvailableSubCommands}}{{$cmds := .Commands}}{{if eq (len .Groups) 0}}

Available Commands:{{range $cmds}}{{if (or .IsAvailableCommand (eq .Name "help"))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{else}}{{range $group := .Groups}}

{{.Title}}{{range $cmds}}{{if (and (eq .GroupID $group.ID) (or .IsAvailableCommand (eq .Name "help")))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{if not .AllChildCommandsHaveGroup}}

Additional Commands:{{range $cmds}}{{if (and (eq .GroupID "") (or .IsAvailableCommand (eq .Name "help")))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{end}}{{end}}{{if .HasAvailableLocalFlags}}

%s{{end}}{{if .HasAvailableInheritedFlags}}

Global Flags:
{{.InheritedFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasHelpSubCommands}}

Additional help topics:{{range .Commands}}{{if .IsAdditionalHelpTopicCommand}}
  {{rpad .CommandPath .CommandPathPadding}} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableSubCommands}}

Use "{{.CommandPath}} [command] --help" for more information about a command.{{end}}
`

// groupUsageFunc returns the usage string for the root command and its subcommands with grouped flags.
func groupUsageFunc(c *cobra.Command, groups map[string]*pflag.FlagSet) string {
	var usage, groupUsage string
	localFlags := pflag.NewFlagSet("localFlags", pflag.ExitOnError)
	groupFlags := make(map[string]string)

	keys := slices.Sorted(maps.Keys(groups))
	for _, name := range keys {
		fs := groups[name]
		groupUsage += fmt.Sprintf("\n%s:\n%s", name, fs.FlagUsages())
		fs.VisitAll(func(f *pflag.Flag) {
			groupFlags[f.Name] = f.Usage
		})
	}

	c.LocalFlags().VisitAll(func(f *pflag.Flag) {
		if _, exists := groupFlags[f.Name]; !exists {
			localFlags.AddFlag(f)
		}
	})

	if localFlags.HasFlags() {
		usage += fmt.Sprintf("\nFlags:\n%s", localFlags.FlagUsages())
	}

	if groupUsage != "" {
		usage += groupUsage
	}

	return strings.TrimSpace(usage)
}

// bindCobraFlags binds the viper config values to the cobra flags.
func bindCobraFlags(cmd *cobra.Command) {
	viper := viper.GetViper()

	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		viperKey := strings.ReplaceAll(f.Name, "-", "_")

		if err := viper.BindPFlag(viperKey, f); err != nil {
			log.Printf("Error binding flag %s to viper: %v", f.Name, err)
		}

		if f.DefValue != "" || viper.IsSet(viperKey) {
			viper.SetDefault(viperKey, f.DefValue)
		}
	})
}

// processFalconPrefixedConfigKeys handles configuration keys with falcon_ prefix
// and maps them to their non-prefixed equivalents in viper.
// This allows both client_id and falcon_client_id to work in config files.
func processFalconPrefixedConfigKeys() {
	allSettings := viper.AllSettings()
	for key, value := range allSettings {
		// Check if the key starts with "falcon_"
		if strings.HasPrefix(strings.ToLower(key), "falcon_") {
			// Strip the falcon_ prefix
			strippedKey := strings.TrimPrefix(strings.ToLower(key), "falcon_")

			// Only set if the non-prefixed key is not already set
			if !viper.IsSet(strippedKey) {
				viper.Set(strippedKey, value)
			}
		}
	}
}

// Execute runs the root command.
func Execute() error {
	return rootCmd().Execute()
}
