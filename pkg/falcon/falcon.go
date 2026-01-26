// MIT License
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

package falcon

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"os"
	"regexp"
	"slices"
	"strings"

	"github.com/crowdstrike/falcon-installer/pkg/utils"
	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/installation_tokens"
	"github.com/crowdstrike/gofalcon/falcon/client/sensor_download"
	"github.com/crowdstrike/gofalcon/falcon/client/sensor_update_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
)

var enterpriseLinux = []string{"rhel", "centos", "oracle", "ol", "oraclelinux", "almalinux", "rocky"}

// semverRegex matches semantic version patterns like "7.32.20403".
var semverRegex = regexp.MustCompile(`^\d+\.\d+\.\d+`)

// extractSemver extracts the semantic version from a version string,
// removing any suffixes like " (LTS)" or other trailing content.
// The sensor download API only accepts clean version numbers in FQL queries.
func extractSemver(version string) string {
	match := semverRegex.FindString(version)
	if match != "" {
		return match
	}
	return version
}

// isPermissionDeniedError checks if the error payload contains a 403 permission denied error.
func isPermissionDeniedError(errPayload []byte) bool {
	errStr := string(errPayload)
	return strings.Contains(errStr, "\"code\":403,\"message\":\"access denied, authorization failed\"") ||
		strings.Contains(errStr, "\"code\":403,\"message\":\"access denied, scope not permitted\"")
}

// GetCID gets the Falcon CID from the CrowdStrike API using the SensorDownload API.
func GetCID(ctx context.Context, client *client.CrowdStrikeAPISpecification) (string, error) {
	response, err := client.SensorDownload.GetSensorInstallersCCIDByQuery(&sensor_download.GetSensorInstallersCCIDByQueryParams{
		Context: ctx,
	})
	if err != nil {
		return "", fmt.Errorf("could not get Falcon CID from CrowdStrike Falcon API: %v", err)
	}

	payload := response.GetPayload()
	if err = falcon.AssertNoError(payload.Errors); err != nil {
		return "", fmt.Errorf("error reported when getting Falcon CID from CrowdStrike Falcon API: %v", err)
	}

	if len(payload.Resources) != 1 {
		return "", fmt.Errorf("failed to get Falcon CID: Unexpected API response: %v", payload.Resources)
	}

	return payload.Resources[0], nil

}

// GetMaintenanceToken queries the CrowdStrike API for the maintenance token.
func GetMaintenanceToken(client *client.CrowdStrikeAPISpecification, aid string) string {
	res, err := client.SensorUpdatePolicies.RevealUninstallToken(
		&sensor_update_policies.RevealUninstallTokenParams{
			Body: &models.UninstallTokenRevealUninstallTokenReqV1{
				DeviceID: &aid,
			},
			Context: context.Background(),
		},
	)
	if err != nil {
		errPayload := falcon.ErrorExtractPayload(err)
		if errPayload == nil {
			log.Fatal(falcon.ErrorExplain(err))
		}

		bytes, mErr := errPayload.MarshalBinary()
		if mErr != nil {
			log.Fatal(mErr)
		}

		if isPermissionDeniedError(bytes) {
			slog.Warn("Skipping getting maintenance token because the OAuth scope does not have permission to read maintenance tokens. Please provide the token via CLI or update the OAuth2 client with the `Sensor Update Policies: Write` scope.")
			return ""
		} else {
			log.Fatal(falcon.ErrorExplain(err))
		}
	}

	payload := res.GetPayload()
	if err = falcon.AssertNoError(payload.Errors); err != nil {
		log.Fatal(err)
	}

	return *payload.Resources[0].UninstallToken
}

// getToken queries the CrowdStrike API for the installation token using the token ID.
func getProvToken(client *client.CrowdStrikeAPISpecification, tokenList []string) string {
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

// getTokenList queries the CrowdStrike API for the installation tokens.
func getProvTokenList(client *client.CrowdStrikeAPISpecification) []string {
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

// GetProvisioningToken queries the CrowdStrike API for the sensor provisioning token.
func GetProvisioningToken(client *client.CrowdStrikeAPISpecification) string {
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

		bytes, mErr := errPayload.MarshalBinary()
		if mErr != nil {
			log.Fatal(mErr)
		}

		if isPermissionDeniedError(bytes) {
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
		token = getProvToken(client, getProvTokenList(client))
		slog.Debug("Found suitable Falcon installation token", "Token", token)
	}

	return token
}

// GetSensorUpdatePolicies queries the CrowdStrike API for sensor update policies that match the provided policy name and architecture.
func GetSensorUpdatePolicies(client *client.CrowdStrikeAPISpecification, osType string, arch string, sensorUpdatePolicyName string) string {
	var filter *string
	csPlatformName := ""

	switch osType {
	case "macos":
		csPlatformName = "Mac"
	case "windows":
		csPlatformName = "Windows"
	default:
		csPlatformName = "Linux"
	}

	// Set default sensor update policy name if not provided
	if sensorUpdatePolicyName == "" {
		sensorUpdatePolicyName = "platform_default"
	}

	f := fmt.Sprintf("platform_name:\"%s\"+name.raw:\"%s\"", csPlatformName, sensorUpdatePolicyName)
	slog.Debug("Sensor Update Policy Query", slog.String("Filter", f))
	filter = &f

	res, err := client.SensorUpdatePolicies.QueryCombinedSensorUpdatePoliciesV2(
		&sensor_update_policies.QueryCombinedSensorUpdatePoliciesV2Params{
			Filter:  filter,
			Context: context.Background(),
		},
	)
	if err != nil {
		errPayload := falcon.ErrorExtractPayload(err)
		if errPayload == nil {
			log.Fatal(falcon.ErrorExplain(err))
		}

		bytes, mErr := errPayload.MarshalBinary()
		if mErr != nil {
			log.Fatal(mErr)
		}

		if isPermissionDeniedError(bytes) {
			slog.Warn("Skipping getting sensor version from sensor update policies because the OAuth scope does not have permission to read sensor update policies. If you are using sensor update policies, please provide the token via CLI or update the OAuth2 client with the `Sensor update policies: Read` scope.")
			return ""
		} else {
			log.Fatal(falcon.ErrorExplain(err))
		}
	}

	payload := res.GetPayload()
	if err = falcon.AssertNoError(payload.Errors); err != nil {
		log.Fatal(err)
	}

	sensorVersion := ""
	for _, policy := range payload.Resources {
		if *policy.Enabled && *policy.Settings.Stage == "prod" {
			switch osType {
			case "linux":
				switch arch {
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

// GetSensors queries the CrowdStrike API for Falcon sensors that match the provided OS name, version, and architecture.
func GetSensors(client *client.CrowdStrikeAPISpecification, osName string, osVersion string, osType string, arch string, sensorUpdatePolicyName string, sensorVersion string) []*models.DomainSensorInstallerV2 {
	var filter *string

	if sensorVersion == "" {
		sensorVersion = GetSensorUpdatePolicies(client, osType, arch, sensorUpdatePolicyName)
	}

	if osName != "" {
		osVersionFilter := fmt.Sprintf("*%s*", osVersion)
		if slices.Contains(enterpriseLinux, strings.ToLower(osName)) {
			slog.Debug("Adding wildcard for Enterprise Linux", "Distros", enterpriseLinux, "OS", osName, "Version", osVersion)
			osName = "*RHEL*"
		} else if osName == "amzn" {
			osName = "Amazon Linux"
			osVersionFilter = osVersion
		}

		f := fmt.Sprintf("os:~\"%s\"+os_version:\"%s\"+architectures:\"%s\"", osName, osVersionFilter, arch)
		if sensorVersion != "" {
			sanitizedVersion := extractSemver(sensorVersion)
			f = fmt.Sprintf("%s+version:\"%s\"", f, sanitizedVersion)
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

// QuerySuitableSensor queries the CrowdStrike API for a suitable Falcon sensor that matches the provided OS name, version, and architecture.
func QuerySuitableSensor(client *client.CrowdStrikeAPISpecification, osName string, osVersion string, osType string, arch string, sensorUpdatePolicyName string, sensorVersion string) *models.DomainSensorInstallerV2 {
	for _, sensor := range GetSensors(client, osName, osVersion, osType, arch, sensorUpdatePolicyName, sensorVersion) {
		if strings.Contains(*sensor.OsVersion, osVersion) {
			if *sensor.Version == sensorVersion || sensorVersion == "" {
				slog.Debug("Found suitable Falcon sensor", "Version", *sensor.Version)
				return sensor
			}
		}
	}
	return nil
}

// SensorDownload downloads the Falcon sensor installer using the CrowdStrike API and saves it to the provided directory.
func SensorDownload(client *client.CrowdStrikeAPISpecification, sensor *models.DomainSensorInstallerV2, dir string, filename string) string {
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
