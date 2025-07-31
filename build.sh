#!/bin/bash

# Build script for WayHack CLI (Go version)

set -e

echo "🔨 Building WayHack CLI (Go version)..."

# Create dist directory
mkdir -p dist

# Build for different platforms
echo "📦 Building for Windows (amd64)..."
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o dist/wayhack-windows-amd64.exe .

echo "📦 Building for Linux (amd64)..."
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o dist/wayhack-linux-amd64 .

echo "📦 Building for macOS (amd64)..."
GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o dist/wayhack-darwin-amd64 .

echo "📦 Building for macOS (arm64)..."
GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o dist/wayhack-darwin-arm64 .

echo "📦 Building for Linux (arm64)..."
GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o dist/wayhack-linux-arm64 .

echo "✅ Build completed! Binaries are in the dist/ directory:"
ls -la dist/

echo ""
echo "📋 Available binaries:"
echo "  - wayhack-windows-amd64.exe (Windows 64-bit)"
echo "  - wayhack-linux-amd64 (Linux 64-bit)"
echo "  - wayhack-darwin-amd64 (macOS Intel)"
echo "  - wayhack-darwin-arm64 (macOS Apple Silicon)"
echo "  - wayhack-linux-arm64 (Linux ARM64)"