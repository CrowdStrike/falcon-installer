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

package dpkg

import (
	"testing"
)

func skipDpkgTests(t *testing.T) {
	if !IsDpkgInstalled() {
		t.Skip("Skipping dpkg tests since dpkg is not installed")
	}
}

func TestIsDpkgInstalled(t *testing.T) {
	dpkgCmd = "/usr/bin/asdfasdf"
	got := IsDpkgInstalled()

	if got {
		t.Errorf("Expected %s not to exist: Got: %v", dpkgCmd, got)
	}

	dpkgCmd = "/usr/bin/dpkg"

	// Skip dpkg query if dpkg is not installed
	skipDpkgTests(t)

	got = IsDpkgInstalled()
	if !got {
		t.Errorf("Expected dpkg to be installed: Got: %v", got)
	}

}

func TestQuery(t *testing.T) {
	dpkgCmd = "/usr/bin/asdfasdf"
	got, err := Query("unknown")
	if err == nil {
		t.Errorf("Expected error: %v", err)
	}

	if got {
		t.Errorf("Expected package not to be installed: Got: %v, Error: %v", got, err)
	}

	dpkgCmd = "/usr/bin/dpkg"

	// Skip dpkg query if dpkg is not installed
	skipDpkgTests(t)

	got, err = Query("dpkg")
	if err != nil {
		t.Error(err)
	}

	if !got {
		t.Errorf("Expected dpkg to be installed: Got: %v, Error: %v", got, err)
	}

	got, err = Query("unknown")
	if err != nil {
		t.Error(err)
	}

	if got {
		t.Errorf("Expected package not to be installed: Got: %v, Error: %v", got, err)
	}

}
