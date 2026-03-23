package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/gshark/sentinel/backend/internal/engine"
	"github.com/gshark/sentinel/backend/internal/model"
	"github.com/gshark/sentinel/backend/internal/plugin"
	"github.com/gshark/sentinel/backend/internal/transport"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	mode := os.Args[1]
	switch mode {
	case "serve":
		runServe(os.Args[2:])
	case "parse":
		runParse(os.Args[2:])
	default:
		usage()
		os.Exit(1)
	}
}

func runServe(args []string) {
	addr := ":17891"
	if len(args) > 0 && args[0] != "" {
		addr = args[0]
	}

	hub := transport.NewHub()
	hub.OnStatus(func(status string) { log.Println("[status]", status) })
	hub.OnError(func(message string) { log.Println("[error]", message) })

	pm := plugin.NewManager()
	_ = pm.LoadFromDir("plugins/rules")

	svc := engine.NewService(hub, pm)
	server := transport.NewServer(svc, hub)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := server.Start(ctx, addr); err != nil {
		log.Fatal(err)
	}
}

func runParse(args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: sentinel parse <capture.pcapng> [display-filter]")
		os.Exit(1)
	}

	hub := transport.NewHub()
	hub.OnStatus(func(status string) { fmt.Println("[status]", status) })
	hub.OnError(func(message string) { fmt.Println("[error]", message) })

	count := 0
	hub.OnPacket(func(packet model.Packet) {
		count++
		if count%500 == 0 {
			fmt.Printf("[packet] #%d %s %s -> %s %s\n", packet.ID, packet.Protocol, packet.SourceIP, packet.DestIP, packet.Info)
		}
	})

	pm := plugin.NewManager()
	_ = pm.LoadFromDir("plugins/rules")
	svc := engine.NewService(hub, pm)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	opts := model.ParseOptions{FilePath: args[0], MaxPackets: 200000, EmitPackets: true}
	if len(args) > 1 {
		opts.DisplayFilter = args[1]
	}

	if err := svc.LoadPCAP(ctx, opts); err != nil {
		fmt.Println("load error:", err)
		os.Exit(1)
	}

	fmt.Println("parsed packets:", len(svc.Packets()))
	printJSON("threat-hits", svc.ThreatHunt([]string{"flag{", "ctf{"}))
	printJSON("objects", svc.Objects())
	printJSON("plugins", svc.ListPlugins())
}

func usage() {
	fmt.Println("Usage:")
	fmt.Println("  sentinel serve [addr]")
	fmt.Println("  sentinel parse <capture.pcapng> [display-filter]")
}

func printJSON(name string, v any) {
	payload, _ := json.MarshalIndent(v, "", "  ")
	fmt.Printf("%s:\n%s\n", name, string(payload))
}
