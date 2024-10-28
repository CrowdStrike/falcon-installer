package cli

import (
	"fmt"
	"io"
	"log"
	"log/slog"
	"maps"
	"os"
	"regexp"
	"runtime"
	"slices"
	"strings"

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

	defaultTmpDir = fmt.Sprint(os.TempDir(), string(os.PathSeparator), "falcon")
	logFile       = fmt.Sprint(defaultTmpDir, string(os.PathSeparator), "falcon-installer.log")
	fi            = installer.FalconInstaller{}
	fc            = installer.FalconSensorCLI{}
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
		PreRunE:          preRunValidation,
		Run:              Run,
	}

	rootCmd.PersistentFlags().StringVar(&fi.TmpDir, "tmpdir", defaultTmpDir, "Temporary directory for downloading files")
	rootCmd.PersistentFlags().Bool("quiet", false, "Suppress all log output")
	rootCmd.PersistentFlags().Bool("enable-file-logging", false, "Output logs to file")
	rootCmd.PersistentFlags().BoolP("help", "h", false, "Print usage information")
	rootCmd.PersistentFlags().BoolP("version", "v", false, "Print version information")
	rootCmd.PersistentFlags().Bool("verbose", false, "Enable verbose output")

	groups := map[string]*pflag.FlagSet{}

	// Falcon API flags
	apiFlag := pflag.NewFlagSet("FalconAPI", pflag.ExitOnError)
	apiFlag.StringVar(&fi.ClientId, "client-id", "", "Client ID for accessing CrowdStrike Falcon Platform")
	apiFlag.StringVar(&fi.ClientSecret, "client-secret", "", "Client Secret for accessing CrowdStrike Falcon Platform")
	apiFlag.StringVar(&fi.MemberCID, "member-cid", "", "Member CID for MSSP (for cases when OAuth2 authenticates multiple CIDs)")
	apiFlag.StringVar(&fi.Cloud, "cloud", "autodiscover", "Falcon cloud abbreviation (e.g. us-1, us-2, eu-1, us-gov-1)")
	apiFlag.StringVar(&fi.SensorUpdatePolicyName, "sensor-update-policy", "platform_default", "The sensor update policy name to use for sensor installation")
	apiFlag.StringVar(&fi.UserAgent, "user-agent", "", "User agent string to append to use for API requests")
	rootCmd.Flags().AddFlagSet(apiFlag)
	err := viper.BindPFlags(apiFlag)
	if err != nil {
		log.Fatalf("Error binding falcon api flags: %v", err)
	}
	groups["Falcon API Flags"] = apiFlag

	// Falcon sensor flags
	falconFlag := pflag.NewFlagSet("Falcon", pflag.ExitOnError)
	falconFlag.StringVar(&fc.CID, "cid", "", "Falcon Customer ID. Optional when OAuth2 token is provided")
	falconFlag.StringVar(&fc.ProvisioningToken, "provisioning-token", "",
		"The provisioning token to use for installing the sensor. If not provided, the API will attempt to retrieve a token")
	falconFlag.StringVar(&fc.Tags, "tags", "", "A comma separated list of tags for sensor grouping")
	falconFlag.StringVar(&fc.APD, "disable-proxy", "", "Configures if the proxy should be enabled or disabled. By default, the proxy is enabled")
	falconFlag.StringVar(&fc.APH, "proxy-host", "", "The proxy host for the sensor to use when communicating with CrowdStrike")
	falconFlag.StringVar(&fc.APP, "proxy-port", "", "The proxy port for the sensor to use when communicating with CrowdStrike")
	rootCmd.Flags().AddFlagSet(falconFlag)
	err = viper.BindPFlags(falconFlag)
	if err != nil {
		log.Fatalf("Error binding falcon sensor flags: %v", err)
	}
	groups["Falcon Sensor Flags"] = falconFlag

	// Linux sensor flags
	if targetOS == "linux" {
		linuxFlag := pflag.NewFlagSet("Linux", pflag.ExitOnError)
		linuxFlag.StringVar(&fi.GpgKeyFile, "gpg-key", "", "Falcon GPG key to import")
		rootCmd.Flags().AddFlagSet(linuxFlag)
		err = viper.BindPFlags(linuxFlag)
		if err != nil {
			log.Fatalf("Error binding linux flags: %v", err)
		}
		groups["Linux Installation Flags"] = linuxFlag
	}

	// Windows sensor flags
	if targetOS == "windows" {
		winFlag := pflag.NewFlagSet("Windows", pflag.ExitOnError)
		winFlag.BoolVar(&fc.Restart, "restart", false, "Allow the system to restart after sensor installation if necessary")
		winFlag.StringVar(&fc.PACURL, "pac-url", "", "Configure a proxy connection using the URL of a PAC file when communicating with CrowdStrike")
		winFlag.BoolVar(&fc.DisableProvisioningWait, "disable-provisioning-wait", false, "Disabling allows the Windows installer more provisioning time")
		winFlag.Uint64Var(&fc.ProvisioningWaitTime, "provisioning-wait-time", 1200000, "The number of milliseconds to wait for the sensor to provision")
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
func preRunConfig(cmd *cobra.Command, args []string) {
	// Check if running with privileges to install Falcon sensor
	privs, err := osutils.RunningWithPrivileges(targetOS)
	if !privs || err != nil {
		log.Fatalf("%v", err)
	}

	viper.SetEnvPrefix("FALCON")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	viper.AutomaticEnv()
	bindCobraFlags(cmd)

	verbose := cmd.Flags().Changed("verbose")
	quiet := cmd.Flags().Changed("quiet")
	enableFileLogging := cmd.Flags().Changed("enable-file-logging")

	if cmd.Flags().Changed("tmpdir") {
		logFile = fmt.Sprintf("%s%s%s", fi.TmpDir, string(os.PathSeparator), "falcon-installer.log")
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

	//create tmp directory if it does not exist
	if _, err := os.Stat(fi.TmpDir); os.IsNotExist(err) {
		if err := os.MkdirAll(fi.TmpDir, 0700); err != nil {
			log.Fatalf("Error creating temporary directory: %v", err)
		}
	}
}

// preRunValidation validates the input flags before running the command.
func preRunValidation(cmd *cobra.Command, args []string) error {
	viper := viper.GetViper()

	if !cmd.Flags().Changed("client-id") && !viper.IsSet("client_id") {
		return fmt.Errorf("Client ID must be specified. See https://falcon.crowdstrike.com/api-clients-and-keys/clients to create or update OAuth2 credentials.")
	}

	if !cmd.Flags().Changed("client-secret") && !viper.IsSet("client_secret") {
		return fmt.Errorf("Client Secret must be specified. See https://falcon.crowdstrike.com/api-clients-and-keys/clients to create or update OAuth2 credentials.")
	}

	if cmd.Flags().Changed("client-id") && viper.GetString("client-id") == "" {
		return fmt.Errorf("Client ID cannot be empty")
	}

	if cmd.Flags().Changed("client-secret") && viper.GetString("client-secret") == "" {
		return fmt.Errorf("Client Secret cannot be empty")
	}

	if err := inputValidation(viper.GetString("client_id"), "^[a-zA-Z0-9]{32}$"); err != nil {
		return fmt.Errorf("Invalid OAuth Client ID format: %v", err)
	}

	if err := inputValidation(viper.GetString("client_secret"), "^[a-zA-Z0-9]{40}$"); err != nil {
		return fmt.Errorf("Invalid OAuth Client Secret format: %v", err)
	}

	if err := inputValidation(viper.GetString("cid"), "^[0-9a-fA-F]{32}-[0-9a-fA-F]{2}$"); err != nil {
		return fmt.Errorf("Invalid CID format: %v", err)
	}

	if err := inputValidation(viper.GetString("member_cid"), "^[0-9a-fA-F]{32}-[0-9a-fA-F]{2}$"); err != nil {
		return fmt.Errorf("Invalid member CID format: %v", err)
	}

	if err := inputValidation(viper.GetString("cloud"), "^(autodiscover|us-1|us-2|eu-1|us-gov-1|gov1)$"); err != nil {
		return fmt.Errorf("Invalid cloud region: %v", err)
	}

	if err := inputValidation(viper.GetString("tags"), "^[a-zA-Z0-9,_/-]+$"); err != nil {
		return fmt.Errorf("Invalid Falcon Sensor tag format: %v", err)
	}

	return nil
}

// Run is the main entry point for the root command.
func Run(cmd *cobra.Command, args []string) {
	if fi.UserAgent != "" {
		fi.UserAgent = fmt.Sprintf("falcon-installer/%s %s", version.Version, fi.UserAgent)
	} else {
		fi.UserAgent = fmt.Sprintf("falcon-installer/%s", version.Version)
	}
	slog.Debug("User agent string", "UserAgent", fi.UserAgent)

	osName, osVersion, err := osutils.ReadEtcRelease(targetOS)
	if err != nil {
		log.Fatalf("%v", err)
	}

	slog.Debug("Identified operating system", "OS", osName, "Version", osVersion)
	osVersion = strings.Split(osVersion, ".")[0]

	fi.Arch = arch
	fi.OS = targetOS
	fi.OsName = osName
	fi.OsVersion = osVersion
	fi.SensorConfig = fc

	slog.Debug("Falcon sensor CLI options", "CID", fc.CID, "ProvisioningToken", fc.ProvisioningToken, "Tags", fc.Tags, "APD", fc.APD, "APH", fc.APH, "APP", fc.APP)
	slog.Debug("Falcon installer options", "Cloud", fi.Cloud, "MemberCID", fi.MemberCID, "SensorUpdatePolicyName", fi.SensorUpdatePolicyName, "GpgKeyFile", fi.GpgKeyFile, "TmpDir", fi.TmpDir, "OsName", fi.OsName, "OsVersion", fi.OsVersion, "OS", fi.OS, "Arch", fi.Arch, "UserAgent", fi.UserAgent)

	installer.Run(fi)
}

// inputValidation validates the input against the provided regex pattern.
func inputValidation(input, pattern string) error {
	if input == "" {
		return nil
	}

	if !regexp.MustCompile(pattern).MatchString(input) {
		return fmt.Errorf("Pattern does not match: %s", pattern)
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
		// Apply the viper config value to the flag when the flag is not set and viper has a value
		if !f.Changed && viper.IsSet(f.Name) {
			val := viper.Get(f.Name)
			if err := cmd.Flags().Set(f.Name, fmt.Sprintf("%v", val)); err != nil {
				log.Fatalf("Error setting flag %s: %v", f.Name, err)
			}
		}
	})
}

// Execute runs the root command.
func Execute() error {
	return rootCmd().Execute()
}
