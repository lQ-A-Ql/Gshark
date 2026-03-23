# Wails Packaging Entry

This folder documents how to package GShark-Sentinel as a desktop app with Wails.

## Build Tags

Wails entrypoint code is under:

- cmd/wails/main.go
- cmd/wails/app.go

Both files use build tag `wails` so regular backend builds are unaffected.

## Local Build Steps

1. Build frontend assets:

```powershell
cd ../../frontend
npm run build
```

2. Install Wails CLI (if not installed):

```powershell
go install github.com/wailsapp/wails/v2/cmd/wails@latest
```

3. Run desktop app from backend root:

```powershell
cd ..
wails dev -tags wails
```

## Notes

- The Wails app binds directly to backend engine service APIs.
- Runtime events emitted to frontend channels: packet, status, error.
