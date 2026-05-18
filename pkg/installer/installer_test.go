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

package installer

import (
	"slices"
	"testing"
)

func TestFormatArg(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		osType   string
		arg      string
		val      string
		expected string
	}{
		{
			name:     "linux cloud",
			osType:   "linux",
			arg:      "cloud",
			val:      "us-1",
			expected: "--cloud=us-1",
		},
		{
			name:     "windows cloud",
			osType:   "windows",
			arg:      "cloud",
			val:      "us-1",
			expected: "CLOUD_NAME=us-1",
		},
		{
			name:     "linux cid",
			osType:   "linux",
			arg:      "cid",
			val:      "ABC123",
			expected: "--cid=ABC123",
		},
		{
			name:     "windows cid",
			osType:   "windows",
			arg:      "cid",
			val:      "ABC123",
			expected: "CID=ABC123",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fi := FalconInstaller{OSType: tc.osType}
			got := fi.formatArg(tc.arg, tc.val)
			if got != tc.expected {
				t.Errorf("formatArg(%q, %q) on %s = %q, want %q", tc.arg, tc.val, tc.osType, got, tc.expected)
			}
		})
	}
}

func TestAddCommonConfigArgs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		fi       FalconInstaller
		initial  []string
		expected []string
	}{
		{
			name: "cloud set on linux",
			fi: FalconInstaller{
				OSType:       "linux",
				SensorConfig: FalconSensorCLI{Cloud: "us-1"},
			},
			initial:  []string{"-sf"},
			expected: []string{"-sf", "--cloud=us-1"},
		},
		{
			name: "cloud empty omitted",
			fi: FalconInstaller{
				OSType:       "linux",
				SensorConfig: FalconSensorCLI{},
			},
			initial:  []string{"-sf"},
			expected: []string{"-sf"},
		},
		{
			name: "cloud with cid and tags",
			fi: FalconInstaller{
				OSType: "linux",
				SensorConfig: FalconSensorCLI{
					CID:   "ABCDEF1234567890ABCDEF1234567890-12",
					Tags:  "tag1,tag2",
					Cloud: "eu-1",
				},
			},
			initial:  []string{"-sf"},
			expected: []string{"-sf", "--cid=ABCDEF1234567890ABCDEF1234567890-12", "--tags=tag1,tag2", "--cloud=eu-1"},
		},
		{
			name: "windows cloud",
			fi: FalconInstaller{
				OSType:       "windows",
				SensorConfig: FalconSensorCLI{Cloud: "us-gov-2"},
			},
			initial:  []string{"/install", "/quiet"},
			expected: []string{"/install", "/quiet", "CLOUD_NAME=us-gov-2"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := tc.fi.addCommonConfigArgs(tc.initial)
			if !slices.Equal(got, tc.expected) {
				t.Errorf("addCommonConfigArgs() = %v, want %v", got, tc.expected)
			}
		})
	}
}

func TestBuildMacOSArgs_License(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		fi       FalconInstaller
		expected []string
	}{
		{
			name: "cloud set",
			fi: FalconInstaller{
				OSType: "macos",
				SensorConfig: FalconSensorCLI{
					CID:   "ABCDEF1234567890ABCDEF1234567890-12",
					Cloud: "us-1",
				},
			},
			expected: []string{"license", "ABCDEF1234567890ABCDEF1234567890-12", "--cloud", "us-1"},
		},
		{
			name: "cloud empty",
			fi: FalconInstaller{
				OSType: "macos",
				SensorConfig: FalconSensorCLI{
					CID: "ABCDEF1234567890ABCDEF1234567890-12",
				},
			},
			expected: []string{"license", "ABCDEF1234567890ABCDEF1234567890-12"},
		},
		{
			name: "cloud with provisioning token",
			fi: FalconInstaller{
				OSType: "macos",
				SensorConfig: FalconSensorCLI{
					CID:               "ABCDEF1234567890ABCDEF1234567890-12",
					ProvisioningToken: "ABCD1234",
					Cloud:             "eu-1",
				},
			},
			expected: []string{"license", "ABCDEF1234567890ABCDEF1234567890-12", "ABCD1234", "--cloud", "eu-1"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := tc.fi.buildMacOSArgs("license")
			if !slices.Equal(got, tc.expected) {
				t.Errorf("buildMacOSArgs(license) = %v, want %v", got, tc.expected)
			}
		})
	}
}

func TestBuildMacOSArgs_NonLicense(t *testing.T) {
	t.Parallel()

	fi := FalconInstaller{
		OSType: "macos",
		SensorConfig: FalconSensorCLI{
			CID:   "ABCDEF1234567890ABCDEF1234567890-12",
			Cloud: "us-1",
			Tags:  "tag1",
		},
	}

	commands := []string{"load", "unload"}
	for _, cmd := range commands {
		t.Run(cmd, func(t *testing.T) {
			t.Parallel()
			got := fi.buildMacOSArgs(cmd)
			for _, arg := range got {
				if arg == "--cloud" || arg == "us-1" {
					t.Errorf("buildMacOSArgs(%q) should not contain cloud args, got %v", cmd, got)
					break
				}
			}
		})
	}
}
