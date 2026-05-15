//go:build !dev && !production

package main

import "fmt"

func main() {
	fmt.Println("This project is a Wails desktop app. Use 'wails build' or 'wails dev'.")
}
