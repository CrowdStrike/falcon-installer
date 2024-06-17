# falcon-installer
A lightweight, multi-platform sensor installer written in Golang

## Building

### Linux
```
go build -o falcon-installer cmd/main.go
```

### Windows
```
go build -o falcon-installer.exe cmd/main.go
```

## Usage

```
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
  -enable-file-logging
    	Log output to file /tmp/falcon/falcon-installer.log
  -gpg-key string
    	Falcon GPG key to import
  -member-cid string
    	Member CID for MSSP (for cases when OAuth2 authenticates multiple CIDs)
  -provisioning-token string
    	The provisioning token to use for installing the sensor
  -sensor-update-policy string
    	The sensor update policy to use for sensor installation
  -tags string
    	A comma seperated list of tags for sensor grouping.
  -tmpdir string
    	Temporary directory for downloading files (default "/tmp/falcon")
  -verbose
    	Enable verbose output
  -version
    	Print version information and exit
```
