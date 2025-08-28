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
>   > Use this scope when using the `--sensor-update-policy` flag or configuring the `FALCON_SENSOR_UPDATE_POLICY` environment variable.
> - (Optional) Sensor update policies [write]
>   > Required if you want to automatically retrieve a maintenance token from the API. Not needed when using the
>   > `--maintenance-token` flag or configuring the `FALCON_MAINTENANCE_TOKEN` environment variable. Maintenance
>   > tokens are required to uninstall sensors that have uninstall protection enabled.


## Usage

```shell
Usage:
  falcon-installer [flags]

Flags:
      --config string         A falcon-installer configuration file
      --enable-file-logging   Output logs to file
  -h, --help                  Print usage information
      --quiet                 Suppress all log output
      --tmpdir string         Temporary directory for downloading files (default "/tmp/falcon")
      --verbose               Enable verbose output
  -v, --version               Print version information

Falcon API Flags:
      --access-token string           Access token for accessing CrowdStrike Falcon Platform
      --client-id string              Client ID for accessing CrowdStrike Falcon Platform
      --client-secret string          Client Secret for accessing CrowdStrike Falcon Platform
      --cloud string                  Falcon cloud abbreviation (e.g. us-1, us-2, eu-1, us-gov-1) (default "autodiscover")
      --member-cid string             Member CID for MSSP (for cases when OAuth2 authenticates multiple CIDs)
      --sensor-update-policy string   The sensor update policy name to use for sensor installation (default "platform_default")
      --sensor-version string         The sensor version to update or install (overrides sensor-update-policy)
      --user-agent string             User agent string to append to use for API requests

Falcon Sensor Flags:
      --cid string                  Falcon Customer ID. Optional when OAuth2 credentials are provided
      --disable-proxy               Disable the sensor proxy settings
      --maintenance-token string    Maintenance token for uninstalling the sensor or configuring sensor settings
      --provisioning-token string   The provisioning token to use for installing the sensor. If not provided, the API will attempt to retrieve a token
      --proxy-host string           The proxy host for the sensor to use when communicating with CrowdStrike
      --proxy-port string           The proxy port for the sensor to use when communicating with CrowdStrike
      --tags string                 A comma separated list of tags for sensor grouping

Falcon Uninstall Flags:
      --uninstall   Uninstall the Falcon sensor

Falcon Update Flags:
      --update   Update the Falcon sensor for when sensor update policies are not in use

Vault Flags:
      --aws-secret-name string      AWS Secrets Manager Secret Name
      --aws-secret-region string    AWS Secrets Manager Region
      --azure-vault-name string     Azure Key Vault Name
      --gcp-project-id string       GCP Project ID for Secret Manager
      --oci-compartment-id string   OCI Compartment ID
      --oci-vault-name string       OCI Vault Name
```

### Linux Specific Arguments

```shell
Linux Installation Flags:
      --configure-image   Use when installing the sensor in an image
      --gpg-key string    Falcon GPG key to import
```

### MacOS Specific Arguments

```shell
MacOS Installation Flags:
      --configure-image   Use when installing the sensor in an image
```

### Windows Specific Arguments

```shell
Windows Installation Flags:
      --disable-provisioning-wait     Disabling allows the Windows installer more provisioning time
      --disable-start                 Prevent the sensor from starting after installation until a reboot occurs
      --pac-url string                Configure a proxy connection using the URL of a PAC file when communicating with CrowdStrike
      --provisioning-wait-time uint   The number of milliseconds to wait for the sensor to provision (default 1200000)
      --restart                       Allow the system to restart after sensor installation if necessary
      --vdi                           Enable virtual desktop infrastructure mode
```

## Installation

- Download a binary release for your targeted operating system of the Falcon Installer from [the official releases page](https://github.com/CrowdStrike/falcon-installer/releases).
- Extract the archive `tar -xvzf <linux-archive>.tar.gz` for Linux and `tar -xf <windows-archive>.zip` for Windows.
- Run the installer setting the CLI flags or environment variables as necessary.

## Building

You can build the binary for either Linux or Windows operating systems from source from within the root of the project directory.

#### Linux and MacOS
```bash
go build -o falcon-installer cmd/main.go
```

#### Windows
```bash
go build -o falcon-installer.exe cmd/main.go
```

Once the binary has been built, you can then manually copy to a location in the local $PATH if desired.

## Usage

The Falcon Installer provides several command-line options to customize the installation process. Below are some common usage examples:

#### Basic Installation
```shell
falcon-installer --client-id YOUR_CLIENT_ID --client-secret YOUR_CLIENT_SECRET
```

#### Installation with Specific Options
```shell
falcon-installer --client-id YOUR_CLIENT_ID --client-secret YOUR_CLIENT_SECRET --cloud us-1 --sensor-update-policy enterprise --tags "tag1,tag2,tag3"
```

#### Installation with Parent/Child CIDs
```shell
falcon-installer --client-id PARENT_CLIENT_ID --client-secret PARENT_CLIENT_SECRET --member-cid MEMBER_CID
```

#### Uninstallation
```shell
falcon-installer --client-id YOUR_CLIENT_ID --client-secret YOUR_CLIENT_SECRET --uninstall
```

#### Update
```shell
falcon-installer --client-id YOUR_CLIENT_ID --client-secret YOUR_CLIENT_SECRET --update --sensor-version 1.42.1234
```

### Using a Configuration File

You can also use a configuration file to specify installation options. The installer supports YAML, JSON, INI, TOML, and HCL formats. See the [examples](examples) directory for sample configuration files.

```shell
falcon-installer --config-file /path/to/config/file
```

### Using Cloud Vaults

The Falcon Installer supports retrieving credentials and configuration from cloud vaults, eliminating the need to store sensitive API credentials in configuration files or environment variables.

#### AWS Secrets Manager

AWS Secrets Manager integration uses the AWS SDK's default credential chain, which supports multiple authentication methods including IAM roles, environment variables, and AWS CLI credentials.

**Prerequisites:**
- AWS Secrets Manager secret containing key-value pairs
- Authentication configured (IAM role, environment variables, or AWS CLI)
- Secret contains Falcon configuration as JSON (e.g. `{"FALCON_CLIENT_ID": "...", "falcon-client-secret": "..."}`)

**Usage:**
```shell
# Using AWS Secrets Manager
falcon-installer --aws-secret-name "falcon-credentials" --aws-secret-region "us-east-1"
```

#### Azure Key Vault

Azure Key Vault integration uses Azure's DefaultAzureCredential authentication, which supports multiple authentication methods including managed identity, Azure CLI, and service principal authentication.

**Prerequisites:**
- Azure Key Vault with appropriate access permissions
- Authentication configured (managed identity, Azure CLI, or service principal)
- Secrets stored with the `falcon-` or `FALCON-` prefix (e.g. `FALCON-CLIENT-ID`, `falcon-client-secret`, etc.)

**Usage:**
```shell
# Using Azure Key Vault
falcon-installer --azure-vault-name "my-keyvault"
```

#### Google Cloud Secret Manager

GCP Secret Manager integration uses Google's Application Default Credentials (ADC), which supports multiple authentication methods including service accounts, workload identity, and gcloud CLI credentials.

**Prerequisites:**
- GCP project with Secret Manager API enabled
- Authentication configured (service account, workload identity, or gcloud CLI)
- Secrets stored with the `falcon_` or `FALCON_` prefix (e.g. `falcon_client_id`, `FALCON_CLIENT_SECRET`, etc.)

**Usage:**
```shell
# Using GCP Secret Manager
falcon-installer --gcp-project-id "my-project-id"
```

#### Oracle Cloud Infrastructure (OCI) Vault

OCI Vault integration uses Instance Principal authentication, designed for use within OCI compute instances.

**Prerequisites:**
- OCI Vault in a specified compartment
- Instance Principal authentication configured
- Compute instance with appropriate IAM policies
- Secrets stored with the `falcon_` or `FALCON_` prefix (e.g. `FALCON_CLIENT_ID`, `falcon_client_secret`, etc.)

**Usage:**
```shell
# Using OCI Vault
falcon-installer --oci-vault-name "my-vault" --oci-compartment-id "ocid1.compartment.oc1..example"
```

## Contributing

We welcome contributions that improve the installation and distribution processes of the Falcon Sensor. Please ensure that your contributions align with our coding standards and pass all CI/CD checks.

## Support

Falcon Installer is a community-driven, open source project designed to streamline the deployment and use of the CrowdStrike Falcon sensor. While not a formal CrowdStrike product, Falcon Installer is maintained by CrowdStrike and supported in partnership with the open source developer community.

For additional support, please see the [SUPPORT.md](SUPPORT.md) file.

## License

See [LICENSE](LICENSE)
