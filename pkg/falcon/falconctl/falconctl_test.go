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

package falconctl

import (
	"runtime"
	"strings"
	"testing"
)

func TestCliConfig(t *testing.T) {
	// Test the cliConfig function
	osType := "macos"
	expected := "/Applications/Falcon.app/Contents/Resources/falconctl"
	actual := cliConfig(osType)
	if actual != expected {
		t.Errorf("cliConfig(%s) = %s; want %s", osType, actual, expected)
	}

	osType = "windows"
	expected = "C:\\Program Files\\CrowdStrike\\CSSensorSettings.exe"
	actual = cliConfig(osType)
	if actual != expected {
		t.Errorf("cliConfig(%s) = %s; want %s", osType, actual, expected)
	}

	osType = "linux"
	expected = "/opt/CrowdStrike/falconctl"
	actual = cliConfig(osType)
	if actual != expected {
		t.Errorf("cliConfig(%s) = %s; want %s", osType, actual, expected)
	}
}

func TestSet(t *testing.T) {
	osType := runtime.GOOS
	args := []string{"--set", "foo=bar"}
	actual := Set("linux", args)
	expected := "Error running falcon command"

	if !strings.Contains(actual.Error(), expected) && !strings.Contains(actual.Error(), "Could not find falcon command") {
		t.Errorf("Set(%s, %v) = %v; want %v", osType, args, actual, expected)
	}
}

func TestGet(t *testing.T) {
	osType := runtime.GOOS
	args := []string{"--get", "foo"}
	_, err := Get(osType, args)
	expected := "Error running falcon command"

	if !strings.Contains(err.Error(), expected) && !strings.Contains(err.Error(), "Could not find falcon command") {
		t.Errorf("Get(%s, %v) = %v; want nil", osType, args, err)
	}
}
