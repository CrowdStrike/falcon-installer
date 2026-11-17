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
	"log"

	"github.com/go-viper/encoding/hcl"
	"github.com/go-viper/encoding/ini"
	"github.com/spf13/viper"
)

// newCodecRegistry returns a codec registry that adds the INI and HCL config
// file formats to the YAML, JSON, TOML, and dotenv formats built into viper.
func newCodecRegistry() *viper.DefaultCodecRegistry {
	registry := viper.NewCodecRegistry()

	codecs := map[string]viper.Codec{
		"ini": ini.Codec{},
		"hcl": hcl.Codec{},
	}
	for format, codec := range codecs {
		if err := registry.RegisterCodec(format, codec); err != nil {
			log.Fatalf("Error registering %s config codec: %v", format, err)
		}
	}

	return registry
}
