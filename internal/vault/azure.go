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
	"fmt"
	"log/slog"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azsecrets"
)

// GetAzureKeyVaultSecrets retrieves secrets from an Azure Key Vault.
func GetAzureKeyVaultSecrets(vaultName string) (map[string]string, error) {
	slog.Debug("Starting secret retrieval process",
		"vaultName", vaultName)

	// Get secrets from vault
	secretValues, err := getAzureSecretsFromVaultByName(vaultName)
	if err != nil {
		return nil, fmt.Errorf("failed to get secrets: %w", err)
	}

	return secretValues, nil
}

// getAzureSecretsFromVaultByName retrieves all secrets from an Azure Key Vault by name and returns them as a map of secret name to secret value.
func getAzureSecretsFromVaultByName(vaultName string) (map[string]string, error) {
	ctx := context.Background()
	secretValues := make(map[string]string)

	// Construct vault URL
	vaultURL := constructVaultURL(vaultName)
	slog.Debug("Constructed vault URL", "vaultURL", vaultURL)

	// Create credential using DefaultAzureCredential
	slog.Debug("Creating Azure credential")
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		slog.Error("Failed to create Azure credential", "error", err)
		return nil, fmt.Errorf("failed to create credential: %w", err)
	}

	// Create the Key Vault secrets client
	slog.Debug("Creating Key Vault secrets client")
	client, err := azsecrets.NewClient(vaultURL, cred, nil)
	if err != nil {
		slog.Error("Failed to create Key Vault client", "error", err)
		return nil, fmt.Errorf("failed to create Key Vault client: %w", err)
	}

	// List all secret properties using pager
	slog.Debug("Listing secrets in vault", "vaultURL", vaultURL)
	pager := client.NewListSecretsPager(nil)
	secretCount := 0

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			slog.Error("Failed to list secrets", "error", err)
			return nil, handleKeyVaultError(err, vaultName)
		}

		slog.Debug("Retrieved secrets page", "count", len(page.Value))

		// Get each secret's value
		for i, secretProps := range page.Value {
			if secretProps.ID == nil {
				slog.Debug("Skipping secret with nil ID", "index", i)
				continue
			}

			// Extract secret name from the ID URL
			secretName := extractSecretNameFromID(string(*secretProps.ID))
			if secretName == "" {
				continue
			}
			slog.Debug("Processing secret", "index", i, "secretName", secretName, "enabled", secretProps.Attributes.Enabled)

			// Get the actual secret value
			secretValue, err := getAzureSecretValue(ctx, client, secretName)
			if err != nil {
				slog.Error("Error getting secret value", "secretName", secretName, "error", err)
				return nil, fmt.Errorf("error getting secret value for %s: %w", secretName, err)
			}

			slog.Debug("Secret retrieved successfully", "secretName", secretName)

			secretName = strings.TrimPrefix(strings.ReplaceAll(strings.ToLower(secretName), "-", "_"), "falcon_")
			slog.Debug("Normalized secret name", "secretName", secretName)
			secretValues[secretName] = secretValue
			secretCount++
		}
	}

	slog.Debug("Completed secret retrieval", "totalSecrets", secretCount)
	return secretValues, nil
}

// getAzureSecretValue retrieves a specific secret value by name from the Azure Key Vault client.
func getAzureSecretValue(ctx context.Context, client *azsecrets.Client, secretName string) (string, error) {
	slog.Debug("Getting secret value", "secretName", secretName)

	// Get the latest version of the secret
	resp, err := client.GetSecret(ctx, secretName, "", nil)
	if err != nil {
		slog.Error("Failed to get secret", "secretName", secretName, "error", err)
		return "", fmt.Errorf("failed to get secret '%s': %w", secretName, err)
	}

	if resp.Value == nil {
		slog.Error("Secret has no value", "secretName", secretName)
		return "", fmt.Errorf("secret '%s' has no value", secretName)
	}

	return *resp.Value, nil
}

// extractSecretNameFromID extracts the secret name from a Key Vault secret ID URL.
func extractSecretNameFromID(id string) string {
	if id == "" {
		return ""
	}

	// Key Vault secret ID format: https://{vault-name}.vault.azure.net/secrets/{secret-name}/{version}
	parts := strings.Split(id, "/")
	if len(parts) >= 5 && parts[3] == "secrets" {
		return parts[4]
	}
	return ""
}

// constructVaultURL constructs the full Azure Key Vault URL from the vault name.
func constructVaultURL(vaultName string) string {
	// If it's already a full URL, return as-is
	if strings.HasPrefix(vaultName, "https://") {
		return vaultName
	}

	// Construct the standard Azure Key Vault URL format
	return fmt.Sprintf("https://%s.vault.azure.net/", vaultName)
}

// handleKeyVaultError provides better error messages for common Key Vault issues.
func handleKeyVaultError(err error, vaultName string) error {
	if err == nil {
		return nil
	}

	errStr := err.Error()

	// Check for common Key Vault error patterns and provide helpful single-line messages
	switch {
	case strings.Contains(errStr, "Invalid issuer"):
		return fmt.Errorf("vault '%s' not found", vaultName)
	case strings.Contains(errStr, "403") || strings.Contains(errStr, "Forbidden"):
		return fmt.Errorf("access denied to vault '%s'", vaultName)
	case strings.Contains(errStr, "404") || strings.Contains(errStr, "NotFound"):
		return fmt.Errorf("vault '%s' not found", vaultName)
	case strings.Contains(errStr, "401") || strings.Contains(errStr, "Unauthorized"):
		return fmt.Errorf("authentication failed for vault '%s'", vaultName)
	default:
		return fmt.Errorf("failed to access vault '%s': %w", vaultName, err)
	}
}
