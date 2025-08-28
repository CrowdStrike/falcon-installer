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
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

// GetAWSSecretsManagerSecrets retrieves a specific secret from AWS Secrets Manager and parses its JSON value as key/value pairs.
func GetAWSSecretsManagerSecrets(region, secretName string) (map[string]string, error) {
	slog.Debug("Starting secret retrieval process", "region", region, "secretName", secretName)

	// Get key/value pairs from the secret
	keyValuePairs, err := getAWSSecretAsKeyValuePairs(region, secretName)
	if err != nil {
		return nil, fmt.Errorf("failed to get secret key/value pairs: %w", err)
	}

	return keyValuePairs, nil
}

// getAWSSecretAsKeyValuePairs retrieves a specific secret from AWS Secrets Manager and parses its JSON value as key/value pairs.
func getAWSSecretAsKeyValuePairs(region, secretName string) (map[string]string, error) {
	slog.Debug("Starting single secret retrieval", "region", region, "secretName", secretName)

	ctx := context.Background()

	// Load AWS configuration
	slog.Debug("Loading AWS configuration", "region", region)
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		slog.Error("Failed to load AWS configuration", "error", err)
		return nil, fmt.Errorf("failed to load AWS configuration: %w", err)
	}

	// Create the Secrets Manager client
	slog.Debug("Creating Secrets Manager client")
	client := secretsmanager.NewFromConfig(cfg)

	// Get the specific secret value
	slog.Debug("Retrieving secret", "secretName", secretName)
	secretValue, err := getAWSSecretValue(ctx, client, secretName)
	if err != nil {
		slog.Error("Error getting secret value", "secretName", secretName, "error", err)
		return nil, fmt.Errorf("error getting secret value for %s: %w", secretName, err)
	}

	slog.Debug("Secret retrieved successfully", "secretName", secretName)

	// Parse JSON key/value pairs from the secret value
	rawKeyValuePairs := make(map[string]string)
	if err := json.Unmarshal([]byte(secretValue), &rawKeyValuePairs); err != nil {
		slog.Error("Failed to parse secret as JSON", "secretName", secretName, "error", err)
		return nil, fmt.Errorf("secret '%s' does not contain valid JSON key/value pairs: %w", secretName, err)
	}

	// Normalize keys: lowercase, convert dashes to underscores, strip "falcon_" prefix
	keyValuePairs := make(map[string]string)
	for rawKey, value := range rawKeyValuePairs {
		normalizedKey := normalizeSecretKey(rawKey)
		keyValuePairs[normalizedKey] = value
		slog.Debug("Normalized secret key name", "key", normalizedKey)
	}

	return keyValuePairs, nil
}

// normalizeSecretKey normalizes a secret key by converting to lowercase, replacing dashes with underscores, and stripping "falcon_" prefix.
func normalizeSecretKey(key string) string {
	// Convert to lowercase and replace dashes with underscores
	normalized := strings.ReplaceAll(strings.ToLower(key), "-", "_")
	// Strip "falcon_" prefix if present
	normalized = strings.TrimPrefix(normalized, "falcon_")
	return normalized
}

// getAWSSecretValue retrieves a specific secret value by name from AWS Secrets Manager.
func getAWSSecretValue(ctx context.Context, client *secretsmanager.Client, secretName string) (string, error) {
	slog.Debug("Getting secret value", "secretName", secretName)

	// Create the request
	input := &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(secretName),
	}

	// Get the secret
	result, err := client.GetSecretValue(ctx, input)
	if err != nil {
		slog.Error("Failed to get secret", "secretName", secretName, "error", err)
		return "", handleAWSSecretsManagerError(err, secretName)
	}

	if result.SecretString == nil {
		slog.Error("Secret has no string value", "secretName", secretName)
		return "", fmt.Errorf("secret '%s' has no string value", secretName)
	}

	return *result.SecretString, nil
}

// handleAWSSecretsManagerError provides better error messages for common Secrets Manager issues.
func handleAWSSecretsManagerError(err error, secretName string) error {
	if err == nil {
		return nil
	}

	errStr := err.Error()

	// Check for common Secrets Manager error patterns and provide helpful single-line messages
	switch {
	case strings.Contains(errStr, "ResourceNotFoundException"):
		return fmt.Errorf("secret '%s' not found", secretName)
	case strings.Contains(errStr, "AccessDeniedException"):
		return fmt.Errorf("access denied to secret '%s'", secretName)
	case strings.Contains(errStr, "UnauthorizedOperation"):
		return fmt.Errorf("unauthorized access to secret '%s'", secretName)
	case strings.Contains(errStr, "InvalidRequestException"):
		return fmt.Errorf("invalid request for secret '%s'", secretName)
	case strings.Contains(errStr, "InvalidParameterException"):
		return fmt.Errorf("invalid parameter for secret '%s'", secretName)
	case strings.Contains(errStr, "DecryptionFailure"):
		return fmt.Errorf("failed to decrypt secret '%s'", secretName)
	case strings.Contains(errStr, "InternalServiceError"):
		return fmt.Errorf("internal service error accessing secret '%s'", secretName)
	default:
		return fmt.Errorf("failed to access secret '%s': %w", secretName, err)
	}
}
