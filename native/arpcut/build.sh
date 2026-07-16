#!/bin/sh
# Build arpcut for Android arm64. Static (no PIE) so it needs no dynamic loader
# on Android; run via `su -c` from the app's nativeLibraryDir as libarpcut.so.
cd "$(dirname "$0")"
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o libarpcut.so .
echo "built: $(file libarpcut.so | cut -d, -f1-3)"
