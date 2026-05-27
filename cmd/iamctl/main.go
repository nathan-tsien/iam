package main

import (
	"fmt"
	"os"

	"github.com/nathan-tsien/iam/internal/cli/iamctl"
)

func main() {
	if err := iamctl.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
