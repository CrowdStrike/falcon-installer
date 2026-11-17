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

package cli

import (
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
)

// TestConfigFileFormats verifies that every config file format documented in
// the README loads the shipped example file with the expected values.
func TestConfigFileFormats(t *testing.T) {
	t.Parallel()

	tests := []struct {
		file string
		// section holds the settings, or "" when they are top-level keys.
		section string
	}{
		{file: "installer.yaml"},
		{file: "installer.json"},
		{file: "installer.toml"},
		{file: "installer.hcl"},
		{file: "installer.ini", section: "falcon"},
	}

	for _, tc := range tests {
		t.Run(tc.file, func(t *testing.T) {
			t.Parallel()

			v := viper.NewWithOptions(viper.WithCodecRegistry(newCodecRegistry()))
			v.SetConfigFile(filepath.Join("..", "..", "examples", tc.file))

			if err := v.ReadInConfig(); err != nil {
				t.Fatalf("ReadInConfig() error = %v", err)
			}

			settings := v
			if tc.section != "" {
				settings = v.Sub(tc.section)
				if settings == nil {
					t.Fatalf("section %q not found", tc.section)
				}
			}

			if got, want := settings.GetString("client_id"), "MY_CLIENT_ID"; got != want {
				t.Errorf("client_id = %q, want %q", got, want)
			}
			if got, want := settings.GetString("client_secret"), "MY_CLIENT_SECRET"; got != want {
				t.Errorf("client_secret = %q, want %q", got, want)
			}
			if got, want := settings.GetString("tags"), "server,production"; got != want {
				t.Errorf("tags = %q, want %q", got, want)
			}
			if !settings.GetBool("configure_image") {
				t.Error("configure_image = false, want true")
			}
			if !settings.GetBool("vdi") {
				t.Error("vdi = false, want true")
			}
		})
	}
}
