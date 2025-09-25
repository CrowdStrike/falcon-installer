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

package config

import (
	"fmt"

	"os"

	"github.com/crowdstrike/falcon-installer/internal/vault"
	"github.com/crowdstrike/falcon-installer/pkg/installer"
	"github.com/spf13/viper"
)

type Config struct {
	installer.FalconInstaller
}

func Load() (*Config, error) {
	var secrets map[string]string
	var err error

	ociVault := viper.GetString("oci_vault_name")
	ociCompartmentID := viper.GetString("oci_compartment_id")
	azureVault := viper.GetString("azure_vault_name")
	managedIdentity := viper.GetString("azure_managed_identity")
	awsSecret := viper.GetString("aws_secret_name")
	awsRegion := viper.GetString("aws_secret_region")
	gcpVault := viper.GetString("gcp_project_id")

	// Check each vault type and load secrets
	switch {
	case awsSecret != "" && awsRegion != "":
		secrets, err = vault.GetAWSSecretsManagerSecrets(awsRegion, awsSecret)
	case azureVault != "":
		{
			if managedIdentity != "" {
				os.Setenv("AZURE_CLIENT_ID", managedIdentity)
			}
			secrets, err = vault.GetAzureKeyVaultSecrets(azureVault)
		}
	case gcpVault != "":
		secrets, err = vault.GetGCPSecretManagerSecrets(gcpVault)
	case ociVault != "" && ociCompartmentID != "":
		secrets, err = vault.GetOCIVaultSecrets(ociCompartmentID, ociVault)
	}

	if err != nil {
		return &Config{}, fmt.Errorf("failed to load config: %w", err)
	}

	for k, v := range secrets {
		viper.Set(k, v)
	}

	c := &Config{}
	c.ClientID = viper.GetString("client_id")
	c.ClientSecret = viper.GetString("client_secret")
	c.AccessToken = viper.GetString("access_token")
	c.Cloud = viper.GetString("cloud")
	c.MemberCID = viper.GetString("member_cid")
	c.SensorUpdatePolicyName = viper.GetString("sensor_update_policy")
	c.SensorVersion = viper.GetString("sensor_version")
	c.GpgKeyFile = viper.GetString("gpg_key")
	c.TmpDir = viper.GetString("tmpdir")
	c.UserAgent = viper.GetString("user_agent")
	c.ConfigureImage = viper.GetBool("configure_image")

	c.SensorConfig.CID = viper.GetString("cid")
	c.SensorConfig.Tags = viper.GetString("tags")
	c.SensorConfig.ProxyHost = viper.GetString("proxy_host")
	c.SensorConfig.ProxyPort = viper.GetString("proxy_port")
	c.SensorConfig.ProxyDisable = viper.GetBool("disable_proxy")
	c.SensorConfig.ProvisioningToken = viper.GetString("provisioning_token")
	c.SensorConfig.MaintenanceToken = viper.GetString("maintenance_token")
	c.SensorConfig.Restart = viper.GetBool("restart")
	c.SensorConfig.NoStart = viper.GetBool("disable_start")
	c.SensorConfig.PACURL = viper.GetString("pac_url")
	c.SensorConfig.DisableProvisioningWait = viper.GetBool("disable_provisioning_wait")
	c.SensorConfig.ProvisioningWaitTime = viper.GetUint64("provisioning_wait_time")
	c.SensorConfig.VDI = viper.GetBool("vdi")

	// Implementation to load configuration
	return c, nil
}
