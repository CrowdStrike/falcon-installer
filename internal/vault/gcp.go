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

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"google.golang.org/api/iterator"
)

// GetGCPSecretManagerSecrets retrieves secrets from a GCP Secret Manager project.
func GetGCPSecretManagerSecrets(projectID string) (map[string]string, error) {
	slog.Debug("Starting secret retrieval process", "projectID", projectID)

	// Get secrets from Secret Manager
	secretValues, err := getGCPSecretsFromProjectByName(projectID)
	if err != nil {
		return nil, fmt.Errorf("failed to get secrets: %w", err)
	}

	return secretValues, nil
}

// getGCPSecretsFromProjectByName retrieves all falcon-prefixed secrets from a GCP Secret Manager project and returns them as a map of secret name to secret value.
func getGCPSecretsFromProjectByName(projectID string) (map[string]string, error) {
	ctx := context.Background()
	secretValues := make(map[string]string)

	// Create the Secret Manager client
	slog.Debug("Creating Secret Manager client")
	client, err := secretmanager.NewClient(ctx)
	if err != nil {
		slog.Error("Failed to create Secret Manager client", "error", err)
		return nil, fmt.Errorf("failed to create Secret Manager client: %w", err)
	}
	defer func() {
		if closeErr := client.Close(); closeErr != nil {
			slog.Error("Failed to close Secret Manager client", "error", closeErr)
		}
	}()

	// List all secrets in the project
	slog.Debug("Listing secrets in project", "projectID", projectID)
	req := &secretmanagerpb.ListSecretsRequest{
		Parent: fmt.Sprintf("projects/%s", projectID),
	}

	secretCount := 0
	it := client.ListSecrets(ctx, req)
	for {
		secret, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			slog.Error("Error iterating over secrets", "error", err)
			return nil, fmt.Errorf("error iterating over secrets: %w", err)
		}

		// Extract secret name from the full resource name
		secretName := extractSecretNameFromResource(secret.Name)
		if secretName == "" {
			continue
		}

		slog.Debug("Processing secret", "secretName", secretName, "resourceName", secret.Name)

		// Get the actual secret value
		secretValue, err := getGCPSecretValue(ctx, client, projectID, secretName)
		if err != nil {
			slog.Error("Error getting secret value", "secretName", secretName, "error", err)
			return nil, fmt.Errorf("error getting secret value for %s: %w", secretName, err)
		}

		slog.Debug("Secret retrieved successfully", "secretName", secretName)

		// Normalize secret name: remove "falcon_" prefix and replace dashes with underscores
		normalizedName := strings.TrimPrefix(strings.ReplaceAll(strings.ToLower(secretName), "-", "_"), "falcon_")
		slog.Debug("Normalized secret name", "secretName", secretName)

		secretValues[normalizedName] = secretValue
		secretCount++
	}

	slog.Debug("Completed secret retrieval", "totalSecrets", secretCount)
	return secretValues, nil
}

// getGCPSecretValue retrieves a specific secret value by name from the GCP Secret Manager.
func getGCPSecretValue(ctx context.Context, client *secretmanager.Client, projectID, secretName string) (string, error) {
	slog.Debug("Getting secret value", "secretName", secretName, "projectID", projectID)

	// Build the secret version name (using "latest" version)
	name := fmt.Sprintf("projects/%s/secrets/%s/versions/latest", projectID, secretName)

	// Create the request
	req := &secretmanagerpb.AccessSecretVersionRequest{
		Name: name,
	}

	// Access the secret
	result, err := client.AccessSecretVersion(ctx, req)
	if err != nil {
		slog.Error("Failed to get secret", "secretName", secretName, "projectID", projectID, "error", err)
		return "", handleGCPSecretManagerError(err, secretName, projectID)
	}

	if result.Payload == nil || result.Payload.Data == nil {
		slog.Error("Secret has no payload", "secretName", secretName)
		return "", fmt.Errorf("secret '%s' has no payload", secretName)
	}

	return string(result.Payload.Data), nil
}

// extractSecretNameFromResource extracts the secret name from a GCP Secret Manager resource name.
func extractSecretNameFromResource(resourceName string) string {
	if resourceName == "" {
		return ""
	}

	// GCP Secret Manager resource name format: projects/{project}/secrets/{secret-name}
	parts := strings.Split(resourceName, "/")
	if len(parts) >= 4 && parts[2] == "secrets" {
		return parts[3]
	}
	return ""
}

// handleGCPSecretManagerError provides better error messages for common Secret Manager issues.
func handleGCPSecretManagerError(err error, secretName, projectID string) error {
	if err == nil {
		return nil
	}

	errStr := err.Error()

	// Check for common Secret Manager error patterns and provide helpful single-line messages
	switch {
	case strings.Contains(errStr, "NotFound") || strings.Contains(errStr, "404"):
		return fmt.Errorf("secret '%s' not found in project '%s'", secretName, projectID)
	case strings.Contains(errStr, "PermissionDenied") || strings.Contains(errStr, "403"):
		return fmt.Errorf("access denied to secret '%s' in project '%s'", secretName, projectID)
	case strings.Contains(errStr, "Unauthenticated") || strings.Contains(errStr, "401"):
		return fmt.Errorf("authentication failed for project '%s'", projectID)
	case strings.Contains(errStr, "InvalidArgument") || strings.Contains(errStr, "400"):
		return fmt.Errorf("invalid request for secret '%s' in project '%s'", secretName, projectID)
	default:
		return fmt.Errorf("failed to access secret '%s' in project '%s': %w", secretName, projectID, err)
	}
}
