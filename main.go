//go:build dev || production

package main

import (
	"embed"
	"log"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	app := NewDesktopApp()
	err := wails.Run(&options.App{
		Title:       "GShark-Sentinel",
		Width:       1680,
		Height:      1020,
		AssetServer: &assetserver.Options{Assets: assets},
		OnStartup:   app.Startup,
		OnShutdown:  app.Shutdown,
		Bind:        []interface{}{app},
	})
	if err != nil {
		log.Fatal(err)
	}
}
