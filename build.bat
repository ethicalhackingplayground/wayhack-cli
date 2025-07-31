@echo off
REM Build script for WayHack CLI (Go version)

echo 🔨 Building WayHack CLI (Go version)...

REM Create dist directory
if not exist dist mkdir dist

REM Build for different platforms
echo 📦 Building for Windows (amd64)...
set GOOS=windows
set GOARCH=amd64
go build -ldflags="-s -w" -o dist/wayhack-windows-amd64.exe .

echo 📦 Building for Linux (amd64)...
set GOOS=linux
set GOARCH=amd64
go build -ldflags="-s -w" -o dist/wayhack-linux-amd64 .

echo 📦 Building for macOS (amd64)...
set GOOS=darwin
set GOARCH=amd64
go build -ldflags="-s -w" -o dist/wayhack-darwin-amd64 .

echo 📦 Building for macOS (arm64)...
set GOOS=darwin
set GOARCH=arm64
go build -ldflags="-s -w" -o dist/wayhack-darwin-arm64 .

echo 📦 Building for Linux (arm64)...
set GOOS=linux
set GOARCH=arm64
go build -ldflags="-s -w" -o dist/wayhack-linux-arm64 .

echo ✅ Build completed! Binaries are in the dist/ directory:
dir dist

echo.
echo 📋 Available binaries:
echo   - wayhack-windows-amd64.exe (Windows 64-bit)
echo   - wayhack-linux-amd64 (Linux 64-bit)
echo   - wayhack-darwin-amd64 (macOS Intel)
echo   - wayhack-darwin-arm64 (macOS Apple Silicon)
echo   - wayhack-linux-arm64 (Linux ARM64)