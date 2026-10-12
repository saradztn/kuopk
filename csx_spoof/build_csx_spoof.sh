#!/usr/bin/env bash
set -euo pipefail
# Build csx_spoof.dll (PE32 x86 Windows DLL) from the faithful CSX spoofer
# replica, plus test_csx_spoof.exe (Windows verification harness).
# Uses zig as a cross-compiler (same toolchain as build_x86.sh).
cd "$(dirname "$0")"

if command -v zig >/dev/null 2>&1; then
    ZIG="zig"
elif [ -x "/tmp/py_zig/ziglang/zig" ]; then
    ZIG="/tmp/py_zig/ziglang/zig"
else
    echo "[!] zig not found; install via: pip install --target /tmp/py_zig ziglang" >&2
    exit 1
fi

mkdir -p ../bin

echo "[*] Compiling csx_spoof.dll (x86-windows-gnu)..."
"$ZIG" c++ -target x86-windows-gnu -std=c++17 -O2 -shared -s \
    -Wl,--subsystem,console -DCSX_SPOOF_BUILD_DLL \
    csx_spoof_core.cpp csx_spoof.def \
    -ladvapi32 -lkernel32 -luser32 \
    -o ../bin/csx_spoof.dll

echo "[*] Compiling test_csx_spoof.exe (x86-windows-gnu)..."
"$ZIG" c++ -target x86-windows-gnu -std=c++17 -O2 -s \
    -Wl,--subsystem,console \
    test_csx_spoof.cpp \
    -ladvapi32 -lkernel32 -luser32 \
    -o "../bin/test_csx_spoof.exe"

echo "[+] Built:"
sha256sum ../bin/csx_spoof.dll "../bin/test_csx_spoof.exe"
