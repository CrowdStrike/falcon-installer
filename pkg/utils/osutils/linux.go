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

//go:build !windows
// +build !windows

package osutils

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/crowdstrike/falcon-installer/pkg/dpkg"
	"github.com/crowdstrike/falcon-installer/pkg/rpm"
	"github.com/crowdstrike/falcon-installer/pkg/utils"
	"go.mozilla.org/pkcs7"
)

// InstalledFalconVersion returns the installed version of the Falcon Sensor on the target OS.
func InstalledFalconVersion(targetOS string) (string, error) {
	switch targetOS {
	case "linux":
		switch {
		case rpm.IsRpmInstalled():
			version, err := rpm.GetVersion("falcon-sensor")
			if err != nil {
				return strings.Join(version, "-"), err
			}

			return strings.Join(version, "-"), nil
		case dpkg.IsDpkgInstalled():
			version, err := dpkg.GetVersion("falcon-sensor")
			if err != nil {
				return version, err
			}
			return version, nil
		default:
			return "", fmt.Errorf("unable to determine Falcon Sensor version. No supported package manager found on Linux")
		}
	case "macos", "darwin":
		args := []string{"--regex", "--pkg-info=com.crowdstrike.falcon.sensor.*"}
		version, stderr, err := utils.RunCmd("pkgutil", args)
		if err != nil {
			return "", fmt.Errorf("error getting Falcon Sensor version: %v, stderr: %s", err, string(stderr))
		}

		// Extract version from pkgutil output
		re := regexp.MustCompile(`version: (.+)`)
		matches := re.FindStringSubmatch(string(version))
		if len(matches) < 2 {
			return "", fmt.Errorf("could not extract version from pkgutil output")
		}

		return strings.TrimSpace(matches[1]), nil
	default:
		return "", fmt.Errorf("unsupported OS for getting Falcon Sensor version: %s", targetOS)
	}
}

// scQuery always returns false for non-Windows operating systems and is used as a placeholder for Windows-specific functionality.
func scQuery(_ string) (bool, error) {
	// This is a non-Windows implementation that always returns false
	return false, fmt.Errorf("service control manager queries not supported on this platform")
}

// DecryptProtectedSettings decrypts CMS encrypted data using the provided certificate and private key.
func DecryptProtectedSettings(protectedSettings string, thumbprint string, keypath string) (map[string]any, error) {
	// Decode the base64 encoded protected settings
	decodedData, err := base64.StdEncoding.DecodeString(protectedSettings)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64: %w", err)
	}

	privateKeyPath := fmt.Sprintf("%s/%s.prv", keypath, thumbprint)
	certPath := fmt.Sprintf("%s/%s.crt", keypath, thumbprint)

	// Read the private key
	privateKeyPEM, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key: %w", err)
	}

	// Parse the private key
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the private key")
	}

	var privateKey interface{}
	privateKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS1 if PKCS8 fails
		privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}
	}

	// Read the certificate
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate: %w", err)
	}

	// Parse the certificate
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the certificate")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Parse the PKCS7 data
	p7, err := pkcs7.Parse(decodedData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS7 data: %w", err)
	}

	// Decrypt the data
	decrypted, err := p7.Decrypt(cert, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	// Parse the decrypted JSON data
	var result map[string]any
	if err := json.Unmarshal(decrypted, &result); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	return result, nil
}
