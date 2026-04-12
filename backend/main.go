//go:build !wails

package main

import "fmt"

func main() {
	fmt.Println("Use cmd/sentinel for CLI/API mode. Desktop mode is built from the repository root with Wails.")
}
