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

package vault

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/common/auth"
	"github.com/oracle/oci-go-sdk/v65/keymanagement"
	"github.com/oracle/oci-go-sdk/v65/secrets"
	"github.com/oracle/oci-go-sdk/v65/vault"
)

// GetOCIVaultSecrets retrieves secrets from an Oracle Cloud Infrastructure (OCI) vault.
func GetOCIVaultSecrets(compartmentID string, vaultName string) (map[string]string, error) {
	slog.Debug("Starting secret retrieval process",
		"compartmentID", compartmentID,
		"vaultName", vaultName)

	// Get secrets from vault
	secretValues, err := getOCISecretsFromVaultByName(compartmentID, vaultName)
	if err != nil {
		return nil, fmt.Errorf("failed to get secrets: %w", err)
	}

	return secretValues, nil
}

// getSecretsFromVaultByName retrieves all secrets from an OCI vault by name and returns them as a map of secret name to secret value.
func getOCISecretsFromVaultByName(compartmentID string, vaultName string) (map[string]string, error) {
	ctx := context.Background()
	secretValues := make(map[string]string)

	// Create provider from instance principal
	provider, err := auth.InstancePrincipalConfigurationProvider()
	if err != nil {
		slog.Error("Failed to create provider", "error", err)
		return nil, fmt.Errorf("failed to create provider: %w", err)
	}

	// Create vault client
	slog.Debug("Creating vault client")
	vaultClient, err := vault.NewVaultsClientWithConfigurationProvider(provider)
	if err != nil {
		slog.Error("Failed to create vault client", "error", err)
		return nil, fmt.Errorf("failed to create vault client: %w", err)
	}

	// Find vault by name
	slog.Debug("Finding vault by name", "vaultName", vaultName)
	vaultID, err := getOCIVaultIDByName(ctx, provider, compartmentID, vaultName)
	if err != nil {
		slog.Error("Failed to find vault", "vaultName", vaultName, "error", err)
		return nil, fmt.Errorf("failed to find vault: %w", err)
	}
	slog.Debug("Found vault", "vaultName", vaultName, "vaultID", vaultID)

	// Create secrets client
	secretsClient, err := secrets.NewSecretsClientWithConfigurationProvider(provider)
	if err != nil {
		slog.Error("Failed to create secrets client", "error", err)
		return nil, fmt.Errorf("failed to create secrets client: %w", err)
	}

	// List secrets in the vault
	slog.Debug("Listing secrets in vault", "vaultID", vaultID)
	secretsReq := vault.ListSecretsRequest{
		CompartmentId: common.String(compartmentID),
		VaultId:       common.String(vaultID),
		Limit:         common.Int(100),
	}

	secretsList, err := vaultClient.ListSecrets(ctx, secretsReq)
	if err != nil {
		slog.Error("Failed to list secrets", "error", err)
		return nil, fmt.Errorf("failed to list secrets: %w", err)
	}
	slog.Debug("Retrieved secrets list", "count", len(secretsList.Items))

	// Get each secret's value
	for i, secretSummary := range secretsList.Items {
		secretID := *secretSummary.Id
		secretName := *secretSummary.SecretName

		slog.Debug("Processing secret",
			"index", i,
			"secretName", secretName,
			"secretID", secretID,
			"lifecycleState", secretSummary.LifecycleState)

		// Get secret bundle
		secretBundleReq := secrets.GetSecretBundleRequest{
			SecretId: common.String(secretID),
		}

		secretBundle, err := secretsClient.GetSecretBundle(ctx, secretBundleReq)
		if err != nil {
			slog.Error("Error getting secret bundle",
				"secretName", secretName,
				"secretID", secretID,
				"error", err)
			return nil, fmt.Errorf("error getting secret bundle for %s: %w", secretName, err)
		}

		contentType := fmt.Sprintf("%T", secretBundle.SecretBundleContent)

		// Ensure we have Base64SecretBundleContentDetails
		base64Content, ok := secretBundle.SecretBundleContent.(secrets.Base64SecretBundleContentDetails)
		if !ok {
			slog.Error("Unexpected secret content type",
				"secretName", secretName,
				"type", contentType)
			return nil, fmt.Errorf("unexpected secret content type for %s: %s", secretName, contentType)
		}

		// Decode base64 content
		content := *base64Content.Content
		slog.Debug("Decoding base64 content",
			"secretName", secretName,
			"contentLength", len(content))

		decodedContent, err := base64.StdEncoding.DecodeString(content)
		if err != nil {
			slog.Error("Error decoding secret",
				"secretName", secretName,
				"error", err)
			return nil, fmt.Errorf("error decoding secret %s: %w", secretName, err)
		}

		secretValues[secretName] = string(decodedContent)
		slog.Debug("Secret decoded successfully",
			"secretName", secretName,
			"decodedLength", len(decodedContent))
	}

	slog.Debug("Completed secret retrieval", "totalSecrets", len(secretValues))
	return secretValues, nil
}

// getOCIVaultIDByName retrieves the OCI vault ID by name from the specified compartment using the provided configuration provider.
func getOCIVaultIDByName(ctx context.Context, provider common.ConfigurationProvider, compartmentID string, vaultName string) (string, error) {
	// Create KMS vault management client
	slog.Debug("Creating KMS vault client")
	kmsClient, err := keymanagement.NewKmsVaultClientWithConfigurationProvider(provider)
	if err != nil {
		slog.Error("Failed to create KMS vault client", "error", err)
		return "", fmt.Errorf("failed to create KMS vault client: %w", err)
	}
	slog.Debug("KMS vault client created successfully")

	// List vaults in compartment
	slog.Debug("Listing vaults in compartment", "compartmentID", compartmentID)
	request := keymanagement.ListVaultsRequest{
		CompartmentId: common.String(compartmentID),
		Limit:         common.Int(100),
	}

	response, err := kmsClient.ListVaults(ctx, request)
	if err != nil {
		slog.Error("Failed to list vaults", "error", err)
		return "", fmt.Errorf("failed to list vaults: %w", err)
	}
	slog.Debug("Retrieved vaults list", "count", len(response.Items))

	// Find vault by name
	slog.Debug("Searching for vault by name", "vaultName", vaultName)
	for i, vault := range response.Items {
		vaultDisplayName := *vault.DisplayName
		vaultID := *vault.Id
		vaultState := vault.LifecycleState

		slog.Debug("Checking vault",
			"index", i,
			"vaultName", vaultDisplayName,
			"vaultID", vaultID,
			"lifecycleState", vaultState)

		if vaultDisplayName == vaultName {
			slog.Debug("Found matching vault",
				"vaultName", vaultName,
				"vaultID", vaultID,
				"lifecycleState", vaultState)

			return vaultID, nil
		}
	}

	// If vault not found in first page, handle pagination
	pageNum := 1
	for response.OpcNextPage != nil {
		pageNum++
		slog.Debug("Checking next page of vaults", "pageNum", pageNum, "nextPageToken", *response.OpcNextPage)

		request.Page = response.OpcNextPage
		response, err = kmsClient.ListVaults(ctx, request)
		if err != nil {
			slog.Error("Failed to list vaults (pagination)", "pageNum", pageNum, "error", err)
			return "", fmt.Errorf("failed to list vaults (pagination): %w", err)
		}
		slog.Debug("Retrieved additional vaults", "pageNum", pageNum, "count", len(response.Items))

		for i, vault := range response.Items {
			vaultDisplayName := *vault.DisplayName
			vaultID := *vault.Id
			vaultState := vault.LifecycleState

			slog.Debug("Checking vault",
				"pageNum", pageNum,
				"index", i,
				"vaultName", vaultDisplayName,
				"vaultID", vaultID,
				"lifecycleState", vaultState)

			if vaultDisplayName == vaultName {
				slog.Debug("Found matching vault",
					"vaultName", vaultName,
					"vaultID", vaultID,
					"lifecycleState", vaultState,
					"pageNum", pageNum)
				return vaultID, nil
			}
		}
	}

	slog.Error("Vault not found", "vaultName", vaultName)
	return "", fmt.Errorf("vault with name %s not found", vaultName)
}
