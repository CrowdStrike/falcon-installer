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

```bash
Usage of falcon-installer:
  -apd string
        Configures if the proxy should be enabled or disabled, By default, the proxy is enabled.
  -aph string
        The proxy host for the sensor to use when communicating with CrowdStrike
  -app string
        The proxy port for the sensor to use when communicating with CrowdStrike
  -cid string
        Falcon Customer ID
  -client-id string
        Client ID for accessing CrowdStrike Falcon Platform (default taken from FALCON_CLIENT_ID env)
  -client-secret string
        Client Secret for accessing CrowdStrike Falcon Platform (default taken from FALCON_CLIENT_SECRET)
  -cloud string
        Falcon cloud abbreviation (us-1, us-2, eu-1, us-gov-1)
  -enable-logging
        Output logs to file /tmp/falcon/falcon-installer.log
  -gpg-key string
        Falcon GPG key to import
  -member-cid string
        Member CID for MSSP (for cases when OAuth2 authenticates multiple CIDs)
  -provisioning-token string
        The provisioning token to use for installing the sensor
  -quiet
        Supress all log output
  -sensor-update-policy string
        The sensor update policy name to use for sensor installation
  -tags string
        A comma seperated list of tags for sensor grouping.
  -tmpdir string
        Temporary directory for downloading files (default "/tmp/falcon")
  -user-agent string
        User agent string to add to use for API requests in addition to the default
  -verbose
        Enable verbose output
  -version
        Print version information and exit
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
