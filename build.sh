#!/bin/bash

# 🚁 SSH Pilot Build Script
# Builds binaries for multiple platforms

set -e

APP_NAME="ssh-pilot"
VERSION=${VERSION:-"1.0.0"}
BUILD_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Get git commit hash if available
if command -v git >/dev/null 2>&1 && [ -d .git ]; then
    GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
else
    GIT_COMMIT="unknown"
fi

# Build flags
LDFLAGS="-s -w -X main.Version=${VERSION} -X main.BuildTime=${BUILD_TIME} -X main.GitCommit=${GIT_COMMIT}"

echo "🚁 Building SSH Pilot v${VERSION}"
echo "Build time: ${BUILD_TIME}"
echo "Git commit: ${GIT_COMMIT}"
echo ""

# Clean previous builds
echo "🧹 Cleaning previous builds..."
rm -rf builds
mkdir -p builds

# Build for multiple platforms
echo "🔨 Building binaries..."

# Linux AMD64
echo "  📦 Building for Linux AMD64..."
GOOS=linux GOARCH=amd64 go build -ldflags="${LDFLAGS}" -o builds/${APP_NAME}-linux-amd64 .

# Linux ARM64 (for Raspberry Pi 4, Apple Silicon servers)
echo "  📦 Building for Linux ARM64..."
GOOS=linux GOARCH=arm64 go build -ldflags="${LDFLAGS}" -o builds/${APP_NAME}-linux-arm64 .

# Linux ARM (for Raspberry Pi older models)
echo "  📦 Building for Linux ARM..."
GOOS=linux GOARCH=arm GOARM=7 go build -ldflags="${LDFLAGS}" -o builds/${APP_NAME}-linux-arm .

# macOS AMD64
echo "  📦 Building for macOS AMD64..."
GOOS=darwin GOARCH=amd64 go build -ldflags="${LDFLAGS}" -o builds/${APP_NAME}-darwin-amd64 .

# macOS ARM64 (Apple Silicon)
echo "  📦 Building for macOS ARM64..."
GOOS=darwin GOARCH=arm64 go build -ldflags="${LDFLAGS}" -o builds/${APP_NAME}-darwin-arm64 .

# Windows AMD64
echo "  📦 Building for Windows AMD64..."
GOOS=windows GOARCH=amd64 go build -ldflags="${LDFLAGS}" -o builds/${APP_NAME}-windows-amd64.exe .

echo ""
echo "✅ Build complete!"
echo ""
echo "📁 Platform-specific builds:"
ls -la builds/

echo ""
echo "🚀 Quick start:"
echo "  ./builds/${APP_NAME}-linux-amd64 --help"
echo "  ./builds/${APP_NAME}-linux-amd64"
echo ""
echo "🌐 SSH Pilot will start on http://localhost:8081"
echo "   Default login: admin / admin"
echo "" 