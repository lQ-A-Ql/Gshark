//go:build bindings && !dev && !production

package main

const (
	currentBuildMode       = "bindings"
	selfUpdateEnabledBuild = false
)
