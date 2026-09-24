#!/bin/sh
# Build arpcut for Android. Static (no PIE) so it needs no dynamic loader
# on Android; run via `su -c` from the app's nativeLibraryDir as libarpcut.so.
set -eu
cd "$(dirname "$0")"
output_dir=${ARPCUT_OUTPUT_DIR:-../../app/build/generated/arpcut/jniLibs}
if [ "$#" -eq 0 ]; then
    set -- arm64-v8a armeabi-v7a x86 x86_64
fi
# Validate every argument before producing output.
for abi in "$@"; do
    case "$abi" in
        arm64-v8a|armeabi-v7a|x86|x86_64) ;;
        *) echo "Unsupported Android ABI: $abi" >&2; exit 2 ;;
    esac
done
if ! command -v go >/dev/null 2>&1; then
    echo "Go 1.24 or newer is required to build arpcut; add go to PATH." >&2
    exit 1
fi
for abi in "$@"; do
    case "$abi" in
        arm64-v8a) arch=arm64 ;;
        armeabi-v7a) arch=arm ;;
        x86) arch=386 ;;
        x86_64) arch=amd64 ;;
    esac
    mkdir -p "$output_dir/$abi"
    CGO_ENABLED=0 GOOS=linux GOARCH="$arch" GOARM=7 GOAMD64=v1 GO386=sse2 \
        go build -trimpath -ldflags="-s -w" -o "$output_dir/$abi/libarpcut.so" .
    echo "Built $abi: $output_dir/$abi/libarpcut.so"
done
