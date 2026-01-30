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

package falcon

import "testing"

func TestExtractSemver(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"LTS suffix", "7.32.20403 (LTS)", "7.32.20403"},
		{"N-1 suffix", "7.31.19999 (N-1)", "7.31.19999"},
		{"arbitrary string suffix", "7.31.1234 some_string", "7.31.1234"},
		{"no suffix", "7.32.20403", "7.32.20403"},
		{"empty string", "", ""},
		{"multiple spaces before suffix", "7.32.20403  (LTS)", "7.32.20403"},
		{"no match returns original", "invalid", "invalid"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractSemver(tt.input)
			if result != tt.expected {
				t.Errorf("extractSemver(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}
