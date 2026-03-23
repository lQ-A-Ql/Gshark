//go:build !wails

package main

import "fmt"

func main() {
	fmt.Println("Use cmd/sentinel for CLI/API mode, or build with -tags wails for desktop mode")
}
