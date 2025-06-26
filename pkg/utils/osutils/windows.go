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

//go:build windows
// +build windows

package osutils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc/mgr"
)

// InstalledFalconVersion returns the installed version of the Falcon Sensor on the target OS.
func InstalledFalconVersion(targetOS string) (string, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return "", fmt.Errorf("error opening registry key: %v", err)
	}
	defer k.Close()

	subKeys, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return "", fmt.Errorf("error reading registry subkeys: %v", err)
	}

	// Look for CrowdStrike Falcon in the uninstall registry keys
	for _, subKey := range subKeys {
		subKeyPath := `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\` + subKey

		subK, err := registry.OpenKey(registry.LOCAL_MACHINE, subKeyPath, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		defer subK.Close()

		displayName, _, err := subK.GetStringValue("DisplayName")
		if err != nil {
			continue
		}
		if strings.Contains(displayName, "CrowdStrike") {
			version, _, err := subK.GetStringValue("DisplayVersion")
			if err != nil {
				continue
			}

			return version, nil
		}
	}

	// If we've checked all subkeys and didn't find CrowdStrike Falcon
	return "", fmt.Errorf("CrowdStrike Falcon version not found in registry")
}

// scQuery queries the Windows service manager for the presence of a service.
func scQuery(name string) (bool, error) {
	// Connect to the Windows service manager
	m, err := mgr.Connect()
	if err != nil {
		return false, fmt.Errorf("failed to connect to service manager: %w", err)
	}
	defer m.Disconnect()

	// Try to open the service
	s, err := m.OpenService(name)
	if err != nil {
		// Check specifically for the "service does not exist" error
		if err == windows.ERROR_SERVICE_DOES_NOT_EXIST {
			return false, nil
		}
		return false, fmt.Errorf("failed to open service %s: %w", name, err)
	}

	// Service exists, close it and return true
	s.Close()
	return true, nil
}

// DecryptProtectedSettings decrypts CMS encrypted data using the provided certificate and private key.
func DecryptProtectedSettings(protectedSettings string, thumbprint string, _ string) (map[string]any, error) {
	// Define the PowerShell function and call it with our parameters
	psScript := `
function Decrypt
{
    [CmdletBinding()]
    [OutputType([System.String])]
    param(
        [Parameter(Position=0, Mandatory=$true)][ValidateNotNullOrEmpty()][System.String]
        $EncryptedBase64String,
        [Parameter(Position=1, Mandatory=$true)][ValidateNotNullOrEmpty()][System.String]
        $CertThumbprint
    )
    [System.Reflection.Assembly]::LoadWithPartialName("System.Security") | out-null
    $encryptedByteArray = [Convert]::FromBase64String($EncryptedBase64String)
    $envelope = New-Object System.Security.Cryptography.Pkcs.EnvelopedCms

    # get certificate from local machine store
    $store = new-object System.Security.Cryptography.X509Certificates.X509Store([System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
    $store.open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
    $cert = $store.Certificates | Where-Object {$_.thumbprint -eq $CertThumbprint}
    if($cert) {
        $envelope.Decode($encryptedByteArray)
        $envelope.Decrypt($cert)
        $decryptedBytes = $envelope.ContentInfo.Content
        $decryptedResult = [System.Text.Encoding]::UTF8.GetString($decryptedBytes)
        Return $decryptedResult
    }
    Return ""
}

$result = Decrypt -EncryptedBase64String "` + protectedSettings + `" -CertThumbprint "` + thumbprint + `"
Write-Output $result
`

	// Execute the PowerShell script
	cmd := exec.Command("powershell", "-ExecutionPolicy", "Bypass", "-Command", psScript)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("PowerShell execution failed: %w\nOutput: %s", err, string(output))
	}

	// Check if output is empty
	if len(bytes.TrimSpace(output)) == 0 {
		return nil, fmt.Errorf("decryption returned empty result, certificate with thumbprint %s might not be found", thumbprint)
	}

	// Parse the JSON output
	var result map[string]any
	if err := json.Unmarshal(output, &result); err != nil {
		// If JSON parsing fails, return both the error and the output for inspection
		previewLen := 100
		if len(output) < previewLen {
			previewLen = len(output)
		}
		return nil, fmt.Errorf("failed to parse JSON: %w (output: %s)",
			err, string(output[:previewLen]))
	}

	return result, nil
}
