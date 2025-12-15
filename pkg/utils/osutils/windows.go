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
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	CERT_FIND_SHA1_HASH   = 0x00010000
	CERT_FIND_SHA256_HASH = 0x00100000
	X509_ASN_ENCODING     = 0x00000001
	PKCS_7_ASN_ENCODING   = 0x00010000

	// Certificate store provider types
	CERT_STORE_PROV_SYSTEM_W = 10

	// Certificate store flags
	CERT_SYSTEM_STORE_LOCAL_MACHINE = 0x00020000
)

var (
	// Load crypt32.dll securely from System32 directory only
	crypt32 = &windows.LazyDLL{
		Name:   "crypt32.dll",
		System: true,
	}

	procCryptDecryptMessage = crypt32.NewProc("CryptDecryptMessage")
)

// cryptDecryptMessagePara structure for CMS decryption parameters.
type cryptDecryptMessagePara struct {
	cbSize                   uint32
	dwMsgAndCertEncodingType uint32
	cCertStore               uint32
	rghCertStore             *uintptr
	dwFlags                  uint32
}

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

// FindCertByFingerprint locates a certificate in the Windows certificate store by its fingerprint.
// The caller is responsible for closing both the store and freeing the certificate context.
func FindCertByFingerprint(storeName string, fingerprint string) (windows.Handle, *windows.CertContext, error) {
	var findType uint32
	var hashBytes []byte
	var err error

	switch len(fingerprint) {
	case 40: // SHA1
		findType = CERT_FIND_SHA1_HASH
		hashBytes, err = hex.DecodeString(fingerprint)
		if err != nil {
			return 0, nil, fmt.Errorf("invalid SHA1 fingerprint format: %w", err)
		}
	case 64: // SHA256
		findType = CERT_FIND_SHA256_HASH
		hashBytes, err = hex.DecodeString(fingerprint)
		if err != nil {
			return 0, nil, fmt.Errorf("invalid SHA256 fingerprint format: %w", err)
		}
	default:
		return 0, nil, fmt.Errorf("unsupported fingerprint length %d (expected 40 for SHA1 or 64 for SHA256)", len(fingerprint))
	}

	storePtr, err := syscall.UTF16PtrFromString(storeName)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to convert store name '%s' to UTF16: %w", storeName, err)
	}

	store, err := windows.CertOpenStore(
		CERT_STORE_PROV_SYSTEM_W,
		0,
		0,
		CERT_SYSTEM_STORE_LOCAL_MACHINE,
		uintptr(unsafe.Pointer(storePtr)),
	)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to open certificate store '%s': %w", storeName, err)
	}
	// Note: Store is returned and will be closed by the caller

	if len(hashBytes) == 0 {
		return 0, nil, fmt.Errorf("hash bytes is empty after decoding fingerprint")
	}

	// Create CRYPT_HASH_BLOB for the fingerprint
	blob := struct {
		cbData uint32
		pbData *byte
	}{
		cbData: uint32(len(hashBytes)),
		pbData: &hashBytes[0],
	}

	// Find certificate by fingerprint
	certContext, err := windows.CertFindCertificateInStore(
		store,
		X509_ASN_ENCODING|PKCS_7_ASN_ENCODING,
		0,
		findType,
		unsafe.Pointer(&blob),
		nil,
	)
	if err != nil {
		return 0, nil, fmt.Errorf("certificate not found with fingerprint %s: %w", fingerprint, err)
	}

	return store, certContext, nil
}

// closeCertStore closes a certificate store handle
func closeCertStore(store windows.Handle) error {
	return windows.CertCloseStore(store, 0)
}

// freeCertContext frees a certificate context
func freeCertContext(certContext *windows.CertContext) error {
	return windows.CertFreeCertificateContext(certContext)
}

// freeCertStoreCertContext frees both the certificate context and the certificate store handle
func freeCertStoreCertContext(store windows.Handle, certContext *windows.CertContext) error {
	err := freeCertContext(certContext)
	if err != nil {
		return err
	}
	err = closeCertStore(store)
	if err != nil {
		return err
	}

	return nil
}

// DecryptProtectedSettings decrypts Azure VM extension protected settings using Windows Crypto API.
func DecryptProtectedSettings(protectedSettings string, fingerprint string, _ string) (map[string]any, error) {
	cmsData, err := base64.StdEncoding.DecodeString(protectedSettings)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 data: %v", err)
	}

	if len(cmsData) == 0 {
		return nil, fmt.Errorf("empty CMS data provided")
	}

	store, certContext, err := FindCertByFingerprint("my", fingerprint)
	if err != nil {
		return nil, fmt.Errorf("failed to find certificate: %v", err)
	}

	if certContext == nil {
		closeErr := closeCertStore(store)
		if closeErr != nil {
			return nil, fmt.Errorf("unable to close the certificate store: %w", closeErr)
		}
		return nil, fmt.Errorf("certificate context is nil")
	}

	// Use Windows Crypto API to decrypt the CMS envelope directly
	decryptedData, err := decryptWithWindowsCryptoAPI(cmsData, store)
	if err != nil {
		resourceErr := freeCertStoreCertContext(store, certContext)
		if resourceErr != nil {
			return nil, fmt.Errorf("resource cleanup failed: %w", resourceErr)
		}
		return nil, fmt.Errorf("CMS envelope decryption failed: %w", err)
	}

	cleanErr := freeCertStoreCertContext(store, certContext)
	if cleanErr != nil {
		return nil, fmt.Errorf("resource cleanup failed: %w", cleanErr)
	}

	// Parse the JSON output
	var result map[string]any
	if err := json.Unmarshal(decryptedData, &result); err != nil {
		// If JSON parsing fails, return both the error and the output for inspection
		previewLen := 100
		if len(decryptedData) < previewLen {
			previewLen = len(decryptedData)
		}
		return nil, fmt.Errorf("failed to parse JSON: %w (output: %s)",
			err, string(decryptedData[:previewLen]))
	}

	return result, nil
}

// cryptDecryptMessage decrypts a CMS/PKCS#7 message using the recipient's certificate
func cryptDecryptMessage(pDecryptPara uintptr, pbEncryptedBlob *byte, cbEncryptedBlob uint32, pbDecryptedBlob *byte, pcbDecryptedBlob *uint32, ppXchgCert **windows.CertContext) error {
	ret, _, err := procCryptDecryptMessage.Call(
		pDecryptPara,
		uintptr(unsafe.Pointer(pbEncryptedBlob)),
		uintptr(cbEncryptedBlob),
		uintptr(unsafe.Pointer(pbDecryptedBlob)),
		uintptr(unsafe.Pointer(pcbDecryptedBlob)),
		uintptr(unsafe.Pointer(ppXchgCert)),
	)
	if ret == 0 {
		return err
	}
	return nil
}

// decryptWithWindowsCryptoAPI uses Windows Crypto API CryptDecryptMessage for direct CMS decryption
func decryptWithWindowsCryptoAPI(cmsData []byte, store windows.Handle) ([]byte, error) {
	hCertStorePtr := uintptr(store)
	decryptPara := cryptDecryptMessagePara{
		cbSize:                   uint32(unsafe.Sizeof(cryptDecryptMessagePara{})),
		dwMsgAndCertEncodingType: X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
		cCertStore:               1,
		rghCertStore:             &hCertStorePtr,
		dwFlags:                  0,
	}

	// First call to get the required size
	var decryptedSize uint32
	err := cryptDecryptMessage(
		uintptr(unsafe.Pointer(&decryptPara)),
		&cmsData[0],
		uint32(len(cmsData)),
		nil,
		&decryptedSize,
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get decrypted message size: %w", err)
	}

	if decryptedSize == 0 {
		return nil, fmt.Errorf("decryption returned zero size")
	}

	// Second call to get the actual decrypted data
	decryptedData := make([]byte, decryptedSize)
	var actualSize = decryptedSize
	err = cryptDecryptMessage(
		uintptr(unsafe.Pointer(&decryptPara)),
		&cmsData[0],
		uint32(len(cmsData)),
		&decryptedData[0],
		&actualSize,
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt message: %w", err)
	}

	if actualSize > decryptedSize {
		return nil, fmt.Errorf("decryption size validation failed: actual size (%d) exceeds expected size (%d)", actualSize, decryptedSize)
	}

	// Trim to actual size
	if actualSize < decryptedSize {
		decryptedData = decryptedData[:actualSize]
	}

	return decryptedData, nil
}
