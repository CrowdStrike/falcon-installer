package main

import (
	"github.com/crowdstrike/falcon-installer/internal/cli"
)

func main() {
	cli.Execute() //nolint:errcheck
}
