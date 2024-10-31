# falcon-installer
A lightweight, multi-platform CrowdStrike Falcon sensor installer written in Golang

## Falcon API Permissions

API clients are granted one or more API scopes. Scopes allow access to specific CrowdStrike APIs and describe the actions that an API client can perform.

Ensure the following API scopes are enabled:

> [!IMPORTANT]
> - **Sensor Download** [read]
> - (optional) **Installation Tokens** [read]
>   > This scope allows the installer to retrieve a provisioning token from the API, but only if installation tokens are required in your environment.
> - (optional) **Sensor update policies** [read]
>   > Use this scope when configuring the `FALCON_SENSOR_UPDATE_POLICY_NAME` environment variable.

## Usage

```shell
Usage:
  falcon-installer [flags]

Flags:
      --enable-file-logging   Output logs to file
  -h, --help                  Print usage information
      --quiet                 Suppress all log output
      --tmpdir string         Temporary directory for downloading files (default "/tmp/falcon")
      --verbose               Enable verbose output
  -v, --version               Print version information

Falcon API Flags:
      --client-id string              Client ID for accessing CrowdStrike Falcon Platform
      --client-secret string          Client Secret for accessing CrowdStrike Falcon Platform
      --cloud string                  Falcon cloud abbreviation (e.g. us-1, us-2, eu-1, us-gov-1) (default "autodiscover")
      --member-cid string             Member CID for MSSP (for cases when OAuth2 authenticates multiple CIDs)
      --sensor-update-policy string   The sensor update policy name to use for sensor installation (default "platform_default")
      --user-agent string             User agent string to append to use for API requests

Falcon Sensor Flags:
      --cid string                  Falcon Customer ID. Optional when OAuth2 token is provided
      --disable-proxy               Disable the sensor proxy settings
      --provisioning-token string   The provisioning token to use for installing the sensor. If not provided, the API will attempt to retrieve a token
      --proxy-host string           The proxy host for the sensor to use when communicating with CrowdStrike
      --proxy-port string           The proxy port for the sensor to use when communicating with CrowdStrike
      --tags string                 A comma separated list of tags for sensor grouping
```

### Linux Specific Arguments

```shell
Linux Installation Flags:
      --gpg-key string   Falcon GPG key to import
```

### Windows Specific Arguments

```shell
Windows Installation Flags:
      --disable-provisioning-wait     Disabling allows the Windows installer more provisioning time
      --pac-url string                Configure a proxy connection using the URL of a PAC file when communicating with CrowdStrike
      --provisioning-wait-time uint   The number of milliseconds to wait for the sensor to provision (default 1200000)
      --restart                       Allow the system to restart after sensor installation if necessary
```

## Installation

- Download a binary release for your targeted operating system of the Falcon Installer from [the official releases page](https://github.com/CrowdStrike/falcon-installer/releases).
- Extract the archive `tar -xvzf <linux-archive>.tar.gz` for Linux and `tar -xf <windows-archive>.zip` for Windows.
- Run the installer setting the CLI flags or environment variables as necessary.

## Building

You can build the binary for either Linux or Windows operating systems from source from within the root of the project directory.

#### Linux
```bash
go build -o falcon-installer cmd/main.go
```

#### Windows
```bash
go build -o falcon-installer.exe cmd/main.go
```

Once the binary has been built, you can then manually copy to a location in the local $PATH if desired.

## Contributing

We welcome contributions that improve the installation and distribution processes of the Falcon Sensor. Please ensure that your contributions align with our coding standards and pass all CI/CD checks.

## Support

Falcon Installer is a community-driven, open source project designed to streamline the deployment and use of the CrowdStrike Falcon sensor. While not a formal CrowdStrike product, Falcon Installer is maintained by CrowdStrike and supported in partnership with the open source developer community.

For additional support, please see the [SUPPORT.md](SUPPORT.md) file.

## License

See [LICENSE](LICENSE)
