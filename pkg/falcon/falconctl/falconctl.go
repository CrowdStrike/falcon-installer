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
	"fmt"
	"log/slog"
	"os/exec"
	"runtime"
	"strings"

	"github.com/crowdstrike/falcon-installer/pkg/utils"
)

// SensorConfig represents the configuration for the Falcon sensor CLI.
type SensorConfig struct {
	// Path to the falconctl binary
	path string
}

// SensorOption defines a functional option for sensor configuration.
type SensorOption func(*sensorOptions)

type sensorOptions struct {
	maintenanceToken *string
}

// WithMaintenanceToken provides a maintenance token for macOS sensor configuration.
func WithSensorMaintenanceTokenOption(token string) SensorOption {
	return func(o *sensorOptions) {
		o.maintenanceToken = &token
	}
}

// NewSensorConfig creates a new SensorConfig for the specified OS.
func NewSensorConfig(osType string) *SensorConfig {
	return &SensorConfig{
		path: getCliPath(osType),
	}
}

// getCliPath returns the path to the Falcon sensor command line interface based on the OS type.
func getCliPath(osType string) string {
	switch osType {
	case "macos", "darwin":
		return "/Applications/Falcon.app/Contents/Resources/falconctl"
	case "windows":
		return "C:\\Program Files\\CrowdStrike\\CSSensorSettings.exe"
	default:
		return "/opt/CrowdStrike/falconctl"
	}
}

// Set configures the Falcon sensor.
// For macOS, an optional maintenance token can be provided.
func (s *SensorConfig) Set(args []string, options ...SensorOption) error {
	// Apply options
	opts := &sensorOptions{}
	for _, option := range options {
		option(opts)
	}

	return s.configure(args, opts.maintenanceToken)
}

// Get retrieves the Falcon sensor settings using the OS-specific command.
func (s *SensorConfig) Get(args []string) (string, error) {
	slog.Debug("Getting sensor settings", "command", s.path, "args", args)

	if err := s.validatePath(); err != nil {
		return "", err
	}

	stdout, stderr, err := utils.RunCmd(s.path, args)
	if err != nil {
		return "", fmt.Errorf("failed to get sensor settings: %w (stderr: %s)", err, stderr)
	}

	return string(stdout), nil
}

// configure sets up the Falcon sensor using the OS-specific command.
func (s *SensorConfig) configure(args []string, maintenanceToken *string) error {
	slog.Debug("Configuring Falcon sensor", "command", s.path, "args", args)

	if err := s.validatePath(); err != nil {
		return err
	}

	// Handle macOS maintenance token case
	if runtime.GOOS == "darwin" && maintenanceToken != nil {
		_, stderr, err := utils.RunCmd(s.path, args,
			utils.WithCmdStdinOption(strings.NewReader(*maintenanceToken)))
		if err != nil {
			return fmt.Errorf("failed to configure sensor with maintenance token: %w (stderr: %s)",
				err, stderr)
		}
		return nil
	}

	// Standard configuration
	_, stderr, err := utils.RunCmd(s.path, args)
	if err != nil {
		return fmt.Errorf("failed to configure sensor: %w (stderr: %s)", err, stderr)
	}

	return nil
}

// validatePath ensures the falconctl binary exists.
func (s *SensorConfig) validatePath() error {
	if _, err := exec.LookPath(s.path); err != nil {
		return fmt.Errorf("falcon command not found at %s: %w", s.path, err)
	}
	return nil
}

// Set configures the Falcon sensor for the specified OS.
// For macOS, an optional maintenance token can be provided.
func Set(args []string, options ...SensorOption) error {
	config := NewSensorConfig(runtime.GOOS)
	return config.Set(args, options...)
}

// Get retrieves the Falcon sensor settings for the specified OS.
func Get(args []string) (string, error) {
	config := NewSensorConfig(runtime.GOOS)
	return config.Get(args)
}
