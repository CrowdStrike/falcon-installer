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
	"strings"

	"github.com/crowdstrike/falcon-installer/internal/vault"
	"github.com/crowdstrike/falcon-installer/pkg/installer"
	"github.com/spf13/viper"
)

type Config struct {
	installer.FalconInstaller
}

func Load() (*Config, error) {
	ociVault := viper.GetString("oci_vault_name")
	ociCompartmentID := viper.GetString("oci_compartment_id")

	if ociVault != "" && ociCompartmentID != "" {
		// Get secrets from OCI vault
		secrets, err := vault.GetOCIVaultSecrets(ociCompartmentID, ociVault)
		if err != nil {
			return nil, fmt.Errorf("failed to load config: %w", err)
		}
		for k, v := range secrets {
			if strings.Contains(k, "FALCON_") {
				key, _ := strings.CutPrefix(k, "FALCON_")
				viper.Set(key, v)
			}
		}
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
