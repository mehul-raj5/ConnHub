#!/bin/bash
mkdir -p dist

echo "Building for Windows..."
GOOS=windows GOARCH=amd64 go build -o dist/client.exe ./Clients
if [ $? -eq 0 ]; then
    echo "Windows build successful."
else
    echo "Windows build failed."
fi

echo "Building for macOS (Intel)..."
GOOS=darwin GOARCH=amd64 go build -o dist/client_mac_intel ./Clients
if [ $? -eq 0 ]; then
    echo "macOS (Intel) build successful."
else
    echo "macOS (Intel) build failed."
fi

echo "Building for macOS (Apple Silicon)..."
GOOS=darwin GOARCH=arm64 go build -o dist/client_mac_silicon ./Clients
if [ $? -eq 0 ]; then
    echo "macOS (Apple Silicon) build successful."
else
    echo "macOS (Apple Silicon) build failed."
fi

echo "Building for Linux..."
GOOS=linux GOARCH=amd64 go build -o dist/client_linux ./Clients
if [ $? -eq 0 ]; then
    echo "Linux build successful."
else
    echo "Linux build failed."
fi

echo "Build process complete. Check the 'dist' folder."
